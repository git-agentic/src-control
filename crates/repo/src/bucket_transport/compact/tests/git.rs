//! Compaction on a Git carrier (ADR-0057 addendum, ADR-0060): the first-sighting
//! age record, leased deletes, and the races and crashes around them. Most tests
//! run over a real `GitBucket` on a `file://` bare hub with an injected clock
//! (`CompactOptions.now`); the exhaustive failure-boundary loop and the
//! idx-sizing test run over an in-memory double with Git's tag semantics (a new
//! tag for every write, real lease checks), which is fast enough to cut at every
//! operation.
//!
//! Every wrapper here forwards `list_tags` and `delete_leased` explicitly: a
//! wrapper that did not would silently get the trait defaults, an unleased
//! delete, and a lease test through it would pass without testing the lease.

use super::super::sightings::{self, Sightings};
use super::*;
use scl_objio::GitBucket;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicUsize;

fn have_git() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

macro_rules! need_git {
    () => {
        if !have_git() {
            eprintln!("git not available; skipping");
            return;
        }
    };
}

const GRACE: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(24 * 3600);

/// The wall clock in whole seconds, the resolution the record keeps.
fn t0() -> SystemTime {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
}

/// A run at `now` with the grace of one hour.
fn at(now: SystemTime) -> CompactOptions {
    CompactOptions {
        prune_expire: GRACE,
        now: Some(now),
        ..CompactOptions::default()
    }
}

// ---- a bare Git hub ---------------------------------------------------------

/// A bare hub repository on disk, removed on drop.
struct Hub {
    dir: PathBuf,
}

fn git_in(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_remove("GIT_DIR")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let (p, t) = (e.path(), to.join(e.file_name()));
        if p.is_dir() {
            copy_dir(&p, &t);
        } else {
            std::fs::copy(&p, &t).unwrap();
        }
    }
}

impl Hub {
    fn new(tag: &str) -> Hub {
        let root = scratch(tag);
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join("hub.git");
        git_in(&root, &["init", "--bare", "-q", dir.to_str().unwrap()]);
        Hub { dir }
    }

    /// An independent copy of this hub (a new compaction experiment from the same state).
    fn copy(&self, tag: &str) -> Hub {
        let root = scratch(tag);
        let dir = root.join("hub.git");
        copy_dir(&self.dir, &dir);
        Hub { dir }
    }

    fn url(&self) -> String {
        format!("file://{}", self.dir.display())
    }

    /// A compactor/reader over this hub as an `sc+git::` remote.
    fn carrier(&self) -> BucketTransport {
        BucketTransport::open(&format!("sc+git::{}", self.url())).unwrap()
    }

    /// A compactor whose bucket calls pass through `hook(op, key, after)`.
    fn hooked(&self, hook: Hook) -> BucketTransport {
        BucketTransport::build(Box::new(self.wrapped(hook)), true).unwrap()
    }

    /// The bucket behind [`Hub::hooked`], for a test that configures it further.
    fn wrapped(&self, hook: Hook) -> Wrapped {
        Wrapped::new(Box::new(GitBucket::open(&self.url()).unwrap()), hook)
    }

    /// `refs/sc/*` names on the hub, sorted.
    fn refs(&self) -> Vec<String> {
        git_in(
            &self.dir,
            &["for-each-ref", "--format=%(refname)", "refs/sc/"],
        )
        .lines()
        .map(str::to_string)
        .collect()
    }

    /// `refs/sc/*` with their object ids, sorted.
    fn refs_with_oids(&self) -> Vec<String> {
        git_in(
            &self.dir,
            &[
                "for-each-ref",
                "--format=%(refname) %(objectname)",
                "refs/sc/",
            ],
        )
        .lines()
        .map(str::to_string)
        .collect()
    }

    fn count(&self, needle: &str) -> usize {
        self.refs().iter().filter(|r| r.contains(needle)).count()
    }

    /// The age record, if there is one.
    fn record(&self) -> Option<Sightings> {
        match self.bucket().get(sightings::KEY, None).unwrap() {
            Fetched::New { bytes, .. } => Some(Sightings::decode(&bytes, u64::MAX / 2).unwrap()),
            _ => None,
        }
    }
}

impl Store for Hub {
    fn bucket(&self) -> Box<dyn Bucket> {
        Box::new(GitBucket::open(&self.url()).unwrap())
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        if let Some(root) = self.dir.parent() {
            let _ = std::fs::remove_dir_all(root);
            if !std::thread::panicking() {
                assert!(!root.exists(), "scratch dir must be removed");
            }
        }
    }
}

/// 12 one-commit pushes with a checkpoint at 10 on a fresh hub, and the refs
/// they hold.
fn seeded_hub(tag: &str) -> (Hub, Vec<(String, ObjectId)>) {
    let hub = Hub::new(tag);
    let refs = hand_built(&hub, 12, 10);
    (hub, refs)
}

/// An orphan pack: uploaded, never committed. Its hash is the one a push of
/// `commit(label)` uploads, so a later push reuses it byte for byte.
fn orphan(s: &impl Store, label: &str) -> String {
    let (_, objects) = commit(label);
    let (pack, _) = scl_core::pack::build_pack(&objects).unwrap();
    let hash = hex::encode(blake3::hash(&pack).as_bytes());
    open(s).put_pack(&mut std::io::Cursor::new(pack)).unwrap();
    hash
}

/// The refs a store is left with once everything unreferenced is gone: the
/// manifest, the one checkpoint, the one merged pack, and the age record.
fn tight(hub: &Hub) -> Vec<String> {
    let refs = hub.refs();
    assert_eq!(refs.len(), 5, "{refs:?}");
    assert_eq!(hub.count("refs/sc/checkpoints/"), 1);
    assert_eq!(hub.count("refs/sc/packs/"), 2);
    assert_eq!(hub.count("refs/sc/log/"), 0);
    refs
}

// ---- wrappers and doubles ---------------------------------------------------

/// `(operation, key or prefix, after)`: called before (`false`) and after
/// (`true`) each bucket operation; an error stops it.
type Hook = Box<dyn Fn(&str, &str, bool) -> scl_objio::Result<()> + Send>;

/// Forwards every operation, including `list_tags` and `delete_leased`, through
/// a hook. `list_meta` is refused: it downloads every value on a Git carrier, so
/// compaction must never ask for it.
///
/// It can also play the host's caches, both of which a real `GitBucket` has:
/// [`Wrapped::stale_window`] answers a conditional `manifest` read with
/// `Unchanged` while the tag matches the last one served (the 2 s freshness
/// window), and [`Wrapped::pin`] keeps serving the value a create-only key had
/// when it was read (the carrier answers such a key from its cache).
struct Wrapped {
    inner: Box<dyn Bucket>,
    hook: Hook,
    stale_window: bool,
    last_manifest: Mutex<Option<String>>,
    pinned: Mutex<BTreeMap<String, (Vec<u8>, String)>>,
}

impl Wrapped {
    fn new(inner: Box<dyn Bucket>, hook: Hook) -> Wrapped {
        Wrapped {
            inner,
            hook,
            stale_window: false,
            last_manifest: Mutex::new(None),
            pinned: Mutex::new(BTreeMap::new()),
        }
    }

    /// Answer a conditional manifest read from the last tag served, never asking
    /// the bucket: the freshness window of `GitBucket`, made deterministic.
    fn stale_window(mut self) -> Wrapped {
        self.stale_window = true;
        self
    }

    /// Serve `key` as `(bytes, tag)` whatever the bucket now holds.
    fn pin(self, key: &str, bytes: Vec<u8>, tag: String) -> Wrapped {
        self.pinned.lock().unwrap().insert(key.into(), (bytes, tag));
        self
    }

    fn around<T>(
        &self,
        op: &str,
        key: &str,
        f: impl FnOnce() -> scl_objio::Result<T>,
    ) -> scl_objio::Result<T> {
        (self.hook)(op, key, false)?;
        let out = f()?;
        (self.hook)(op, key, true)?;
        Ok(out)
    }
}

impl Bucket for Wrapped {
    fn get(&self, key: &str, tag: Option<&str>) -> scl_objio::Result<Fetched> {
        self.around("get", key, || {
            if let Some((bytes, pinned)) = self.pinned.lock().unwrap().get(key) {
                return Ok(Fetched::New {
                    bytes: bytes.clone(),
                    tag: pinned.clone(),
                });
            }
            if key != "manifest" || !self.stale_window {
                return self.inner.get(key, tag);
            }
            let mut last = self.last_manifest.lock().unwrap();
            if tag.is_some() && tag == last.as_deref() {
                return Ok(Fetched::Unchanged);
            }
            let got = self.inner.get(key, tag)?;
            if let Fetched::New { tag, .. } = &got {
                *last = Some(tag.clone());
            }
            Ok(got)
        })
    }
    fn put_new(&self, key: &str, bytes: &[u8]) -> scl_objio::Result<bool> {
        self.around("put_new", key, || self.inner.put_new(key, bytes))
    }
    fn put_if_tag(
        &self,
        key: &str,
        bytes: &[u8],
        tag: Option<&str>,
    ) -> scl_objio::Result<Option<String>> {
        self.around("put_if_tag", key, || self.inner.put_if_tag(key, bytes, tag))
    }
    fn list(&self, prefix: &str) -> scl_objio::Result<Vec<String>> {
        self.around("list", prefix, || self.inner.list(prefix))
    }
    fn list_meta(&self, _prefix: &str) -> scl_objio::Result<Vec<ObjectMeta>> {
        Err(scl_objio::Error::Backend(
            "list_meta downloads every value on a git carrier and must not be called".into(),
        ))
    }
    fn exists(&self, key: &str) -> scl_objio::Result<bool> {
        self.around("exists", key, || self.inner.exists(key))
    }
    fn delete(&self, key: &str) -> scl_objio::Result<()> {
        self.around("delete", key, || self.inner.delete(key))
    }
    fn list_tags(&self, prefix: &str) -> scl_objio::Result<Vec<(String, String)>> {
        self.around("list_tags", prefix, || self.inner.list_tags(prefix))
    }
    fn delete_leased(&self, items: &[(String, String)]) -> scl_objio::Result<()> {
        let first = items.first().map_or("", |(k, _)| k.as_str());
        self.around("delete_leased", first, || self.inner.delete_leased(items))
    }
}

/// In-memory bucket with Git's tag semantics: every write gets a new tag (a
/// commit with a nonce), so a key that is deleted and uploaded again is a new
/// generation even with identical bytes, and `delete_leased` honors its lease.
#[derive(Default)]
struct GitLike {
    map: Mutex<BTreeMap<String, (Vec<u8>, String)>>,
    writes: AtomicU64,
}

impl GitLike {
    fn tag_for(&self, bytes: &[u8]) -> String {
        let n = self.writes.fetch_add(1, Ordering::SeqCst);
        let mut h = blake3::Hasher::new();
        h.update(bytes);
        h.update(&n.to_le_bytes());
        hex::encode(h.finalize().as_bytes())[..40].to_string()
    }

    fn fork(&self) -> Arc<GitLike> {
        Arc::new(GitLike {
            map: Mutex::new(self.map.lock().unwrap().clone()),
            writes: AtomicU64::new(self.writes.load(Ordering::SeqCst)),
        })
    }
}

struct LikeHandle(Arc<GitLike>);

impl Bucket for LikeHandle {
    fn get(&self, key: &str, cached: Option<&str>) -> scl_objio::Result<Fetched> {
        Ok(match self.0.map.lock().unwrap().get(key) {
            None => Fetched::Absent,
            Some((_, t)) if cached == Some(t.as_str()) => Fetched::Unchanged,
            Some((b, t)) => Fetched::New {
                bytes: b.clone(),
                tag: t.clone(),
            },
        })
    }
    fn put_new(&self, key: &str, bytes: &[u8]) -> scl_objio::Result<bool> {
        let mut m = self.0.map.lock().unwrap();
        if m.contains_key(key) {
            return Ok(false);
        }
        let tag = self.0.tag_for(bytes);
        m.insert(key.into(), (bytes.to_vec(), tag));
        Ok(true)
    }
    fn put_if_tag(
        &self,
        key: &str,
        bytes: &[u8],
        expected: Option<&str>,
    ) -> scl_objio::Result<Option<String>> {
        let mut m = self.0.map.lock().unwrap();
        if m.get(key).map(|(_, t)| t.as_str()) != expected {
            return Ok(None);
        }
        let tag = self.0.tag_for(bytes);
        m.insert(key.into(), (bytes.to_vec(), tag.clone()));
        Ok(Some(tag))
    }
    fn list(&self, prefix: &str) -> scl_objio::Result<Vec<String>> {
        Ok(self
            .list_tags(prefix)?
            .into_iter()
            .map(|(k, _)| k)
            .collect())
    }
    fn list_meta(&self, _prefix: &str) -> scl_objio::Result<Vec<ObjectMeta>> {
        Err(scl_objio::Error::Backend(
            "list_meta must not be called on a git carrier".into(),
        ))
    }
    fn exists(&self, key: &str) -> scl_objio::Result<bool> {
        Ok(self.0.map.lock().unwrap().contains_key(key))
    }
    fn delete(&self, key: &str) -> scl_objio::Result<()> {
        self.0.map.lock().unwrap().remove(key);
        Ok(())
    }
    fn list_tags(&self, prefix: &str) -> scl_objio::Result<Vec<(String, String)>> {
        Ok(self
            .0
            .map
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, (_, t))| (k.clone(), t.clone()))
            .collect())
    }
    fn delete_leased(&self, items: &[(String, String)]) -> scl_objio::Result<()> {
        let mut m = self.0.map.lock().unwrap();
        for (key, tag) in items {
            if m.get(key).is_some_and(|(_, t)| t == tag) {
                m.remove(key);
            }
        }
        Ok(())
    }
}

impl Store for Arc<GitLike> {
    fn bucket(&self) -> Box<dyn Bucket> {
        Box::new(LikeHandle(self.clone()))
    }
}

fn like_carrier(s: &Arc<GitLike>) -> BucketTransport {
    BucketTransport::build(s.bucket(), true).unwrap()
}

/// Push `commit(label)` to branch `label` through a fresh transport on `hub`.
fn push_label(hub: &Hub, label: &str) -> (String, ObjectId) {
    let t = hub.carrier();
    let (tip, objects) = commit(label);
    for (id, bytes) in &objects {
        t.put_object(id, bytes).unwrap();
    }
    t.update_ref(label, &tip, None).unwrap();
    (label.to_string(), tip)
}

// ---- the age record gates every delete --------------------------------------

#[test]
fn the_first_run_deletes_nothing_it_never_saw_and_a_run_past_the_grace_deletes_what_aged() {
    need_git!();
    let (hub, refs) = seeded_hub("git-two-runs");
    let start = t0();
    let before = hub.refs();

    // Run 1: phase 1 merges the 12 small packs; the sweep sees everything for the first time.
    let r1 = hub.carrier().compact(&at(start)).unwrap();
    assert_eq!((r1.packs_merged, r1.packs_created), (12, 1), "{r1:?}");
    assert_eq!(
        (r1.logs_deleted, r1.checkpoints_deleted, r1.packs_deleted),
        (0, 0, 0),
        "{r1:?}"
    );
    assert_eq!(r1.packs_held_back, 12, "{r1:?}");
    assert!(
        r1.notes.iter().any(|n| n.contains("first sighting")),
        "{r1:?}"
    );
    let after1 = hub.refs();
    for r in &before {
        assert!(after1.contains(r), "{r} vanished on the first run");
    }
    // The record names every pack and checkpoint key, first seen now, and no log or manifest.
    let rec = hub.record().expect("the first run wrote the record");
    let tracked: Vec<&str> = after1
        .iter()
        .map(|r| r.strip_prefix("refs/sc/").unwrap())
        .filter(|k| k.starts_with("packs/") || k.starts_with("checkpoints/"))
        .collect();
    assert_eq!(rec.keys(), tracked);
    assert_eq!(tracked.len(), 2 * 13 + 2, "13 packs and 2 checkpoints");
    for k in &tracked {
        assert_eq!(rec.first_seen(k), Some(secs(start)), "{k}");
    }
    assert_readable(&hub, &refs);

    // Run 2, two days later: everything unreferenced has aged.
    let r2 = hub.carrier().compact(&at(start + 2 * DAY)).unwrap();
    assert_eq!(
        (r2.logs_deleted, r2.checkpoints_deleted, r2.packs_deleted),
        (13, 1, 12),
        "{r2:?}"
    );
    assert_eq!(r2.cutoff, 13, "{r2:?}");
    assert!(r2.bytes_deleted > 0, "{r2:?}");
    let left = tight(&hub);
    assert!(left.contains(&"refs/sc/compact/sightings".to_string()));
    assert!(left.contains(&"refs/sc/manifest".to_string()));
    assert_readable(&hub, &refs);

    // Run 3 deletes nothing more and drops the vanished keys from the record.
    let r3 = hub.carrier().compact(&at(start + 2 * DAY)).unwrap();
    assert_eq!(
        (r3.logs_deleted, r3.checkpoints_deleted, r3.packs_deleted),
        (0, 0, 0),
        "{r3:?}"
    );
    assert_eq!(
        hub.record().unwrap().keys().len(),
        3,
        "one pack pair and one checkpoint"
    );
    assert_eq!(tight(&hub), left);
    // The remote still takes pushes and the next one reads back.
    let mut all = refs;
    all.push(push_label(&hub, "after"));
    assert_readable(&hub, &all);
}

#[test]
fn a_record_that_calls_everything_ancient_deletes_only_what_nothing_names() {
    need_git!();
    let (hub, refs) = seeded_hub("git-backdated");
    let start = t0();
    hub.carrier().compact(&at(start)).unwrap();
    let live_before = hub.refs();
    // Anyone who can push can write this record. They can delete directly too, so it
    // adds no authority; but it must never make a live object deletable.
    let b = hub.bucket();
    let Fetched::New { bytes, tag } = b.get(sightings::KEY, None).unwrap() else {
        panic!("no record")
    };
    let text = String::from_utf8(bytes).unwrap();
    let backdated: String = text
        .lines()
        .map(|l| format!("0 {}\n", l.split_once(' ').unwrap().1))
        .collect();
    b.put_if_tag(sightings::KEY, backdated.as_bytes(), Some(&tag))
        .unwrap()
        .unwrap();

    // The very next run, at the same instant, takes the backdated ages at their word.
    let rep = hub.carrier().compact(&at(start)).unwrap();
    assert_eq!(rep.packs_deleted, 12, "{rep:?}");
    tight(&hub);
    // The live merged pack, the current checkpoint and the manifest survived it.
    for needle in ["refs/sc/manifest", "refs/sc/checkpoints/"] {
        assert!(live_before.iter().any(|r| r.contains(needle)));
        assert!(hub.refs().iter().any(|r| r.contains(needle)), "{needle}");
    }
    assert_readable(&hub, &refs);
}

#[test]
fn a_record_that_names_the_manifest_or_a_log_is_refused_and_nothing_is_deleted() {
    need_git!();
    let (hub, refs) = seeded_hub("git-names-manifest");
    let start = t0();
    hub.carrier().compact(&at(start)).unwrap();
    let before = hub.refs_with_oids();
    let b = hub.bucket();
    let Fetched::New { bytes, tag } = b.get(sightings::KEY, None).unwrap() else {
        panic!("no record")
    };
    let text = String::from_utf8(bytes).unwrap();
    // `manifest` sorts between `checkpoints/` and `packs/`; put it there so the
    // only thing wrong with the record is that it names the manifest.
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let pos = lines.iter().position(|l| l.contains(" packs/")).unwrap();
    lines.insert(pos, format!("0 {} manifest", "a".repeat(40)));
    let hostile_text = lines.join("\n") + "\n";
    b.put_if_tag(sightings::KEY, hostile_text.as_bytes(), Some(&tag))
        .unwrap()
        .unwrap();
    let hostile = hub.refs_with_oids();
    let err = hub
        .carrier()
        .compact(&at(start + 2 * DAY))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unusable") && err.contains("delete that ref"),
        "{err}"
    );
    assert_eq!(
        hub.refs_with_oids(),
        hostile,
        "a refused record deletes nothing"
    );
    assert_ne!(before, hostile);
    assert_readable(&hub, &refs);
}

#[test]
fn a_malformed_or_future_record_blocks_compaction_until_it_is_deleted() {
    need_git!();
    let (hub, refs) = seeded_hub("git-malformed");
    let start = t0();
    let b = hub.bucket();
    assert!(b.put_new(sightings::KEY, b"garbage\n").unwrap());
    let planted = hub.refs_with_oids();
    let err = hub.carrier().compact(&at(start)).unwrap_err().to_string();
    assert!(err.contains("unusable"), "{err}");
    assert!(err.contains("refs/sc/compact/sightings"), "{err}");
    assert_eq!(
        hub.refs_with_oids(),
        planted,
        "nothing was merged or deleted"
    );

    // A record from a clock an hour ahead is not read as "everything is young" either.
    let Fetched::New { tag, .. } = b.get(sightings::KEY, None).unwrap() else {
        panic!()
    };
    let future = format!("{} {} packs/x.pack\n", secs(start) + 3600, "b".repeat(40));
    b.put_if_tag(sightings::KEY, future.as_bytes(), Some(&tag))
        .unwrap()
        .unwrap();
    let err = hub.carrier().compact(&at(start)).unwrap_err().to_string();
    assert!(err.contains("clocks disagree"), "{err}");
    assert!(err.contains("delete that ref"), "{err}");
    assert_eq!(hub.count("refs/sc/log/"), 12);

    // The fix the message names works.
    b.delete(sightings::KEY).unwrap();
    hub.carrier().compact(&at(start)).unwrap();
    assert!(hub.record().is_some());
    assert_readable(&hub, &refs);
}

#[test]
fn a_dry_run_writes_no_record_and_reports_what_a_real_run_would_do() {
    need_git!();
    let (hub, refs) = seeded_hub("git-dry");
    let start = t0();
    let before = hub.refs_with_oids();

    // Before any real run: the plan merges and keeps everything; no record appears.
    let dry = hub
        .carrier()
        .compact(&CompactOptions {
            dry_run: true,
            ..at(start)
        })
        .unwrap();
    assert!(dry.dry_run);
    assert_eq!((dry.packs_merged, dry.packs_created), (12, 1), "{dry:?}");
    assert_eq!(dry.packs_deleted, 0, "{dry:?}");
    assert!(
        dry.notes.iter().any(|n| n.contains("lower bound")),
        "{dry:?}"
    );
    assert_eq!(hub.refs_with_oids(), before, "a dry run writes nothing");
    assert!(hub.record().is_none());

    // After a real run, a dry run two days later reports the deletions the real run makes.
    hub.carrier().compact(&at(start)).unwrap();
    let recorded = hub.refs_with_oids();
    let dry = hub
        .carrier()
        .compact(&CompactOptions {
            dry_run: true,
            ..at(start + 2 * DAY)
        })
        .unwrap();
    assert_eq!(
        (dry.logs_deleted, dry.checkpoints_deleted, dry.packs_deleted),
        (13, 1, 12),
        "{dry:?}"
    );
    assert!(dry.bytes_deleted > 0);
    assert_eq!(
        hub.refs_with_oids(),
        recorded,
        "still nothing written or deleted"
    );
    let real = hub.carrier().compact(&at(start + 2 * DAY)).unwrap();
    assert_eq!(
        (
            real.logs_deleted,
            real.checkpoints_deleted,
            real.packs_deleted
        ),
        (13, 1, 12)
    );
    assert_readable(&hub, &refs);
}

// ---- generations, leases and the races around a delete ----------------------

#[test]
fn a_key_deleted_and_uploaded_again_starts_its_age_over() {
    need_git!();
    let (hub, refs) = seeded_hub("git-recreated");
    let start = t0();
    let lone = orphan(&hub, "orphan-a");
    let keys = [format!("packs/{lone}.idx"), format!("packs/{lone}.pack")];
    let exists = |hub: &Hub| keys.iter().all(|k| hub.bucket().exists(k).unwrap());

    hub.carrier().compact(&at(start)).unwrap();
    assert!(exists(&hub));
    let r2 = hub.carrier().compact(&at(start + 2 * DAY)).unwrap();
    assert!(
        !keys.iter().any(|k| hub.bucket().exists(k).unwrap()),
        "{r2:?}"
    );

    // A retried push uploads the same bytes again, without ever committing them.
    assert_eq!(orphan(&hub, "orphan-a"), lone);
    assert!(exists(&hub));
    // Past the old record's grace, but the key is a new generation: it survives.
    let r3 = hub.carrier().compact(&at(start + 2 * DAY)).unwrap();
    assert!(exists(&hub), "{r3:?}");
    assert_eq!(r3.packs_held_back, 1, "{r3:?}");
    let rec = hub.record().unwrap();
    assert_eq!(rec.first_seen(&keys[1]), Some(secs(start + 2 * DAY)));
    // It does age out like any other, from its own first sighting.
    hub.carrier().compact(&at(start + 4 * DAY)).unwrap();
    assert!(!exists(&hub));
    assert_readable(&hub, &refs);
}

#[test]
fn a_key_re_created_between_the_listing_and_the_delete_survives_its_lease() {
    need_git!();
    let (hub, refs) = seeded_hub("git-lease");
    let start = t0();
    let lone = orphan(&hub, "orphan-b");
    let keys = [format!("packs/{lone}.idx"), format!("packs/{lone}.pack")];
    hub.carrier().compact(&at(start)).unwrap();

    let url = hub.url();
    let fired = Arc::new(AtomicBool::new(false));
    let hook_keys = keys.to_vec();
    let hook: Hook = Box::new(move |op, key, after| {
        // Just before the first pack delete: the key is deleted and uploaded
        // again by someone else (the same bytes, a new commit, a new oid).
        if op == "delete_leased"
            && !after
            && key.starts_with("packs/")
            && !fired.swap(true, Ordering::SeqCst)
        {
            let other = GitBucket::open(&url).unwrap();
            for k in &hook_keys {
                let Fetched::New { bytes, .. } = other.get(k, None)? else {
                    panic!("{k} should exist")
                };
                other.delete(k)?;
                assert!(other.put_new(k, &bytes)?);
            }
        }
        Ok(())
    });
    let before: BTreeMap<String, String> = hub
        .bucket()
        .list_tags("packs/")
        .unwrap()
        .into_iter()
        .collect();
    let rep = hub.hooked(hook).compact(&at(start + 2 * DAY)).unwrap();
    // The other 12 old packs went; the re-created one did not, and nothing failed.
    assert_eq!(hub.count("refs/sc/packs/"), 2 + 2, "{:?}", hub.refs());
    let after: BTreeMap<String, String> = hub
        .bucket()
        .list_tags("packs/")
        .unwrap()
        .into_iter()
        .collect();
    for k in &keys {
        assert!(after.contains_key(k), "{k} was destroyed: {rep:?}");
        assert_ne!(after[k], before[k], "{k} should be the re-created value");
    }
    assert_readable(&hub, &refs);
}

/// A pusher reuses an aged orphan pack by identical bytes and its commit lands
/// after the compactor listed, but before the compactor's manifest check. This
/// proves the check, and that it reads the manifest uncached: the bucket here
/// answers a conditional manifest read `Unchanged` from its freshness window
/// (as `GitBucket` does for 2 s), so a check that reused the cached tag would
/// call the manifest unmoved and delete the pack. What it does not prove, and
/// nothing can without a lease on the manifest, is the window between the check
/// and the delete: a commit landing there is the residual race ADR-0057 names.
#[test]
fn a_push_landing_after_the_listing_is_seen_by_the_manifest_check_and_its_pack_kept() {
    need_git!();
    let (hub, mut refs) = seeded_hub("git-late-push");
    let start = t0();
    let lone = orphan(&hub, "late-0");
    let keys = [format!("packs/{lone}.idx"), format!("packs/{lone}.pack")];
    hub.carrier().compact(&at(start)).unwrap();

    let url = hub.url();
    let state = Arc::new(AtomicUsize::new(0));
    let hook: Hook = Box::new(move |op, key, after| {
        match (op, after, state.load(Ordering::SeqCst)) {
            ("list_tags", true, 0) => state.store(1, Ordering::SeqCst),
            // The first manifest read after the listing: a push has just landed.
            ("get", false, 1) if key == "manifest" => {
                state.store(2, Ordering::SeqCst);
                let t = BucketTransport::open(&format!("sc+git::{url}")).unwrap();
                let (tip, objects) = commit("late-0");
                for (id, bytes) in &objects {
                    t.put_object(id, bytes).unwrap();
                }
                t.update_ref("late-0", &tip, None).unwrap();
            }
            _ => {}
        }
        Ok(())
    });
    let t = BucketTransport::build(Box::new(hub.wrapped(hook).stale_window()), true).unwrap();
    let rep = t.compact(&at(start + 2 * DAY)).unwrap();
    for k in &keys {
        assert!(hub.bucket().exists(k).unwrap(), "{k} was deleted: {rep:?}");
    }
    refs.push(("late-0".to_string(), commit("late-0").0));
    assert_readable(&hub, &refs);
    // The replan went on to remove what was still unreferenced.
    assert!(rep.packs_deleted >= 12, "{rep:?}");
    assert_eq!(
        hub.count("refs/sc/log/"),
        1,
        "only the late push's entry is left"
    );
}

#[test]
fn two_compactors_racing_on_the_record_converge() {
    need_git!();
    let (hub, refs) = seeded_hub("git-race");
    let start = t0();
    let url = hub.url();
    let fired = Arc::new(AtomicBool::new(false));
    // Compactor A is about to write the record when compactor B runs to completion.
    let hook: Hook = Box::new(move |op, key, after| {
        if op == "put_if_tag"
            && key == sightings::KEY
            && !after
            && !fired.swap(true, Ordering::SeqCst)
        {
            BucketTransport::open(&format!("sc+git::{url}"))
                .unwrap()
                .compact(&at(start))
                .unwrap();
        }
        Ok(())
    });
    let rep = hub.hooked(hook).compact(&at(start)).unwrap();
    assert_eq!(
        (rep.logs_deleted, rep.checkpoints_deleted, rep.packs_deleted),
        (0, 0, 0),
        "{rep:?}"
    );
    // A's lost compare-and-swap replanned and read B's record: one consistent record.
    let rec = hub.record().unwrap();
    for k in rec.keys() {
        assert_eq!(rec.first_seen(k), Some(secs(start)), "{k}");
    }
    assert_readable(&hub, &refs);
    // Both agree that two days later it is all old.
    let rep = hub.carrier().compact(&at(start + 2 * DAY)).unwrap();
    assert!(rep.packs_deleted > 0, "{rep:?}");
    tight(&hub);
    assert_readable(&hub, &refs);
}

#[test]
fn a_failure_between_the_record_and_each_delete_call_leaves_a_readable_store_a_rerun_finishes() {
    need_git!();
    let (template, refs) = seeded_hub("git-crash");
    let start = t0();
    template.carrier().compact(&at(start)).unwrap();
    // Run 2 makes three delete calls: log entries and checkpoints, then the
    // idx files of the aged packs, then their bodies. Fail before each one.
    for fail_at in 0..3usize {
        let hub = template.copy(&format!("git-crash-{fail_at}"));
        // A pack that appears only now, so the crashing run has something new
        // to record: the record must already hold it when the crash comes.
        let fresh = orphan(&hub, "crash-orphan");
        let fresh_keys = [format!("packs/{fresh}.idx"), format!("packs/{fresh}.pack")];
        let calls = Arc::new(AtomicUsize::new(0));
        let hook: Hook = Box::new(move |op, _, after| {
            if op == "delete_leased" && !after && calls.fetch_add(1, Ordering::SeqCst) == fail_at {
                return Err(scl_objio::Error::Backend("injected crash".into()));
            }
            Ok(())
        });
        let err = hub
            .hooked(hook)
            .compact(&at(start + 2 * DAY))
            .unwrap_err()
            .to_string();
        assert!(err.contains("injected crash"), "{err}");
        // The record was written before the first delete was tried: it already
        // holds the new pack, first seen at this run's time (and not before).
        let rec = hub.record().unwrap();
        for k in &fresh_keys {
            assert_eq!(rec.first_seen(k), Some(secs(start + 2 * DAY)), "{k}");
        }
        // What the crash left is a bucket a cold start reads.
        assert_readable(&hub, &refs);
        match fail_at {
            0 => {
                assert_eq!(hub.count("refs/sc/log/"), 13);
                assert_eq!(hub.count("refs/sc/packs/"), 2 * 14);
            }
            1 => {
                assert_eq!(hub.count("refs/sc/log/"), 0);
                assert_eq!(hub.count("refs/sc/packs/"), 2 * 14);
            }
            _ => {
                // idx files gone, bodies left: plain debris, aged on its own next run
                assert_eq!(hub.count(".idx"), 2);
                assert_eq!(hub.count(".pack"), 14);
            }
        }
        // A healthy rerun finishes the job. The new pack is not old enough yet,
        // so it survives that run, and everything else unreferenced is gone.
        hub.carrier().compact(&at(start + 2 * DAY)).unwrap();
        for k in &fresh_keys {
            assert!(
                hub.bucket().exists(k).unwrap(),
                "{k} was deleted before it aged"
            );
        }
        assert_eq!(hub.refs().len(), 5 + fresh_keys.len(), "{:?}", hub.refs());
        assert_eq!(hub.count("refs/sc/log/"), 0);
        assert_eq!(hub.count("refs/sc/checkpoints/"), 1);
    }
}

#[cfg(unix)]
#[test]
fn a_host_that_refuses_the_deletes_fails_the_run_and_loses_nothing() {
    use std::os::unix::fs::PermissionsExt;
    need_git!();
    let (hub, refs) = seeded_hub("git-refused");
    let start = t0();
    hub.carrier().compact(&at(start)).unwrap();
    // An `update` hook that refuses to delete any pack body (a deletion pushes the zero oid).
    let hook = hub.dir.join("hooks/update");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\ncase \"$1\" in refs/sc/packs/*.pack) if [ \"$3\" = {} ]; then echo 'bodies are kept' >&2; exit 1; fi;; esac\nexit 0\n",
            "0".repeat(40)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = hub
        .carrier()
        .compact(&at(start + 2 * DAY))
        .unwrap_err()
        .to_string();
    assert!(err.contains("bodies are kept"), "{err}");
    assert_readable(&hub, &refs);
    // The host relents: the rerun deletes the leftovers.
    std::fs::remove_file(&hook).unwrap();
    hub.carrier().compact(&at(start + 2 * DAY)).unwrap();
    tight(&hub);
    assert_readable(&hub, &refs);
}

// ---- in-memory: every operation boundary, and sizes from the idx ------------

#[test]
fn a_failure_at_every_operation_boundary_on_a_git_carrier_leaves_a_readable_bucket() {
    let template = Arc::new(GitLike::default());
    let refs = hand_built(&template, 12, 10);
    let mut finished_at = None;
    for budget in 0..5000i64 {
        let work = template.fork();
        let left = Arc::new(AtomicI64::new(budget));
        let tick = left.clone();
        let hook: Hook = Box::new(move |_, _, after| {
            if !after && tick.fetch_sub(1, Ordering::SeqCst) <= 0 {
                return Err(scl_objio::Error::Backend("injected failure".into()));
            }
            Ok(())
        });
        let outcome = BucketTransport::build(Box::new(Wrapped::new(work.bucket(), hook)), true)
            // A zero grace sees every first sighting as already old: one run deletes.
            .and_then(|t| t.compact(&eager()));

        // Whatever happened, a fresh reader still sees everything.
        assert_readable(&work, &refs);
        if outcome.is_ok() && left.load(Ordering::SeqCst) > 0 {
            finished_at = Some(budget);
            break;
        }
        // And a healthy rerun finishes the job.
        like_carrier(&work).compact(&eager()).unwrap();
        assert_readable(&work, &refs);
        assert_eq!(keys(&work, "packs/").len(), 2, "budget {budget}");
        assert!(keys(&work, "log/").is_empty(), "budget {budget}");
        assert_eq!(keys(&work, "checkpoints/").len(), 1, "budget {budget}");
    }
    let n = finished_at.expect("compaction never completed within the budget");
    assert!(n > 20, "the loop should cross many boundaries, got {n}");
}

/// The leased analogue of the pack-deletion stop on the plain backends: a push
/// lands once the first batch of packs is gone, and the next batch's manifest
/// check keeps the rest. (A push landing between a batch's idx and body deletes
/// is `a_reuse_between_the_idx_delete_and_the_body_delete_keeps_the_body`.)
#[test]
fn a_manifest_that_moves_during_leased_pack_deletion_stops_the_deletes() {
    let mem = Arc::new(GitLike::default());
    let refs = push_commits(&open(&mem), "w", 70);
    let fired = Arc::new(AtomicBool::new(false));
    let late = mem.clone();
    let hook: Hook = Box::new(move |op, key, after| {
        // After the bodies of the first batch went: someone else pushes.
        if op == "delete_leased"
            && after
            && key.ends_with(".pack")
            && !fired.swap(true, Ordering::SeqCst)
        {
            push_commits(&open(&late), "late", 1);
        }
        Ok(())
    });
    let t = BucketTransport::build(Box::new(Wrapped::new(mem.bucket(), hook)), true).unwrap();
    let rep = t.compact(&eager()).unwrap();
    assert!(
        rep.notes
            .iter()
            .any(|n| n.contains("moved during pack deletion")),
        "{rep:?}"
    );
    assert_eq!(rep.packs_deleted, PACK_DELETE_BATCH, "{rep:?}");
    assert!(keys(&mem, "packs/").len() > 4);
    let mut all = refs;
    all.push(("late-0".to_string(), commit("late-0").0));
    assert_readable(&mem, &all);
    // A rerun finishes the job.
    like_carrier(&mem).compact(&eager()).unwrap();
    assert_eq!(keys(&mem, "packs/").len(), 2);
    assert_readable(&mem, &all);
}

#[test]
fn the_double_leases_like_git_and_a_replayed_compaction_changes_nothing() {
    // The double itself: a re-created key has a new tag and a stale lease leaves it.
    let scratch_hub = Arc::new(GitLike::default());
    let b = scratch_hub.bucket();
    assert!(b.put_new("packs/a.pack", b"x").unwrap());
    let Fetched::New { tag: old, .. } = b.get("packs/a.pack", None).unwrap() else {
        panic!()
    };
    b.delete("packs/a.pack").unwrap();
    assert!(b.put_new("packs/a.pack", b"x").unwrap());
    b.delete_leased(&[("packs/a.pack".into(), old)]).unwrap();
    assert!(b.exists("packs/a.pack").unwrap());

    // A zero-grace pass leaves a tight store, and a second one changes nothing.
    let mem = Arc::new(GitLike::default());
    let refs = hand_built(&mem, 12, 10);
    like_carrier(&mem).compact(&eager()).unwrap();
    let settled = mem.map.lock().unwrap().clone();
    like_carrier(&mem).compact(&eager()).unwrap();
    assert!(
        settled.keys().eq(mem.map.lock().unwrap().keys()),
        "a replay must not add or remove a key"
    );
    assert_readable(&mem, &refs);
}

/// `idx` with every entry rewritten to start at `offset` and be `length` long:
/// an idx is the writer's word about its pack.
fn lying_idx(idx: &[u8], offset: u64, length: u64) -> Vec<u8> {
    let entries = scl_core::pack::parse_index(idx).unwrap();
    let mut lie = Vec::new();
    lie.extend_from_slice(b"SCIX");
    lie.extend_from_slice(&1u32.to_le_bytes());
    lie.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for e in &entries {
        lie.extend_from_slice(e.id.as_bytes());
        lie.extend_from_slice(&offset.to_le_bytes());
        lie.extend_from_slice(&length.to_le_bytes());
    }
    lie
}

/// A push's objects and the tip it moves a branch to.
type Push = (Vec<(ObjectId, Vec<u8>)>, ObjectId);

/// Build a one-pack-per-push chain by hand; `idx_of` may rewrite a pack's idx.
fn chain(
    b: &dyn Bucket,
    packs: &[Push],
    idx_of: impl Fn(usize, Vec<u8>) -> Vec<u8>,
) -> Vec<String> {
    let mut hashes = Vec::new();
    for (i, (objects, tip)) in packs.iter().enumerate() {
        let (pack, idx) = scl_core::pack::build_pack(objects).unwrap();
        let hash = hex::encode(blake3::hash(&pack).as_bytes());
        b.put_new(&pack_key(&hash), &pack).unwrap();
        b.put_new(&idx_key(&hash), &idx_of(i, idx)).unwrap();
        let seq = i as u64 + 1;
        let entry = LogEntry {
            seq,
            parent_seq: seq - 1,
            packs: vec![hash.clone()],
            updates: vec![RefUpdate {
                branch: format!("b-{seq}"),
                old: None,
                new: *tip,
            }],
        };
        b.put_new(&log_key(seq), &entry.encode()).unwrap();
        hashes.push(hash);
    }
    let m = Manifest {
        head_seq: packs.len() as u64,
        checkpoint_seq: 0,
        head_branch: "b-1".into(),
    };
    b.put_if_tag("manifest", &m.encode(), None)
        .unwrap()
        .unwrap();
    hashes
}

#[test]
fn packs_are_sized_from_their_idx_and_one_far_over_its_idx_is_left_unmerged() {
    // Deterministic bytes zstd cannot shrink, so the pack really is about this long.
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let noise: Vec<u8> = (0..6000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let small = |label: &str| {
        let (tip, objects) = commit(label);
        (objects, tip)
    };
    let big = {
        let blob = Object::blob(noise);
        let tree = Object::Tree(scl_core::Tree::new(vec![scl_core::TreeEntry {
            name: "f".into(),
            kind: scl_core::EntryKind::Blob,
            id: blob.id(),
            mode: scl_core::FileMode(0o644),
            perms: 0,
        }]));
        let snap = Object::Snapshot(scl_core::Snapshot {
            root: tree.id(),
            parents: vec![],
            author: "t".into(),
            timestamp: 1,
            message: "liar".into(),
            secrets: Default::default(),
            protection: Default::default(),
        });
        let objects: Vec<(ObjectId, Vec<u8>)> = [&blob, &tree, &snap]
            .iter()
            .map(|o| (o.id(), o.encode()))
            .collect();
        (objects, snap.id())
    };
    let mem = Arc::new(GitLike::default());
    let hashes = chain(
        mem.bucket().as_ref(),
        &[small("s-1"), small("s-2"), big],
        // The third pack's idx claims it is a dozen bytes long.
        |i, idx| {
            if i != 2 {
                return idx;
            }
            lying_idx(&idx, 8, 1)
        },
    );
    let opts = CompactOptions {
        small_pack_bytes: 2000,
        ..eager()
    };
    // The idx sizes are what plans the merge: no list_meta (the double refuses it).
    let rep = like_carrier(&mem).compact(&opts).unwrap();
    assert_eq!((rep.packs_merged, rep.packs_created), (2, 1), "{rep:?}");
    assert!(
        rep.notes
            .iter()
            .any(|n| n.contains("left unmerged") && n.contains(&hashes[2])),
        "{rep:?}"
    );
    // The over-sized pack is untouched and still on the chain; the honest two are replaced.
    assert!(mem.bucket().exists(&pack_key(&hashes[2])).unwrap());
    assert!(!mem.bucket().exists(&pack_key(&hashes[0])).unwrap());
    let ck = checkpoint_key(manifest(&mem).checkpoint_seq);
    let Fetched::New { bytes, .. } = mem.bucket().get(&ck, None).unwrap() else {
        panic!("no checkpoint")
    };
    let packs = Checkpoint::decode(&bytes).unwrap().packs;
    assert_eq!(packs.len(), 2);
    assert!(packs.contains(&hashes[2]));
}

#[test]
fn the_idx_length_is_the_end_of_the_furthest_record_and_saturates() {
    use scl_core::pack::{build_pack, parse_index, IndexEntry};
    let (_, objects) = commit("sized");
    let (pack, idx) = build_pack(&objects).unwrap();
    let entries = parse_index(&idx).unwrap();
    assert_eq!(declared_pack_len(&entries), pack.len() as u64);
    // an empty pack is its 8-byte header
    let (empty, empty_idx) = build_pack(&[]).unwrap();
    assert_eq!(
        declared_pack_len(&parse_index(&empty_idx).unwrap()),
        empty.len() as u64
    );
    // a hostile idx can only make a pack look large
    let id = objects[0].0;
    let huge = |offset, length| IndexEntry { id, offset, length };
    assert_eq!(declared_pack_len(&[huge(u64::MAX, 1)]), u64::MAX);
    assert_eq!(declared_pack_len(&[huge(8, u64::MAX)]), u64::MAX);
    assert_eq!(declared_pack_len(&[huge(u64::MAX - 3, 0)]), u64::MAX);
}

// ---- review fixes: ages per member, per-attempt clock, retained tags, sums ---

/// A hook that never interferes.
fn quiet() -> Hook {
    Box::new(|_, _, _| Ok(()))
}

/// Put the pack of `commit(label)` straight into `b` as an orphan; `idx_of` may
/// rewrite its idx. Returns the pack hash.
fn put_orphan(b: &dyn Bucket, label: &str, idx_of: impl Fn(Vec<u8>) -> Vec<u8>) -> String {
    let (_, objects) = commit(label);
    let (pack, idx) = scl_core::pack::build_pack(&objects).unwrap();
    let hash = hex::encode(blake3::hash(&pack).as_bytes());
    b.put_new(&pack_key(&hash), &pack).unwrap();
    b.put_new(&idx_key(&hash), &idx_of(idx)).unwrap();
    hash
}

/// The age record in `s`.
fn record_in(s: &impl Store) -> Sightings {
    let Fetched::New { bytes, .. } = s.bucket().get(sightings::KEY, None).unwrap() else {
        panic!("no record")
    };
    Sightings::decode(&bytes, u64::MAX / 2).unwrap()
}

#[test]
fn a_key_first_listed_in_a_run_is_stamped_no_earlier_than_its_listing() {
    let mem = Arc::new(GitLike::default());
    hand_built(&mem, 12, 10);
    let pusher = mem.clone();
    let stalled = Arc::new(AtomicBool::new(false));
    let listing_from = Arc::new(AtomicU64::new(0));
    let (once, from) = (stalled.clone(), listing_from.clone());
    let hook: Hook = Box::new(move |op, _, after| {
        // The compactor stalls before its listing; a push uploads a pack
        // meanwhile, and a while passes before the listing is taken.
        if op == "list_tags" && !after && !once.swap(true, Ordering::SeqCst) {
            put_orphan(pusher.bucket().as_ref(), "stall-0", |idx| idx);
            std::thread::sleep(Duration::from_millis(1100));
            from.store(secs(SystemTime::now()), Ordering::SeqCst);
        }
        Ok(())
    });
    // The wall clock, no injected `now`.
    BucketTransport::build(Box::new(Wrapped::new(mem.bucket(), hook)), true)
        .unwrap()
        .compact(&CompactOptions::default())
        .unwrap();
    assert!(
        stalled.load(Ordering::SeqCst),
        "the listing was never taken"
    );
    let (_, objects) = commit("stall-0");
    let (pack, _) = scl_core::pack::build_pack(&objects).unwrap();
    let hash = hex::encode(blake3::hash(&pack).as_bytes());
    let stamped = record_in(&mem)
        .first_seen(&pack_key(&hash))
        .expect("the pack is tracked");
    assert!(
        stamped >= listing_from.load(Ordering::SeqCst),
        "stamped {stamped}, before the listing that first showed it at {}",
        listing_from.load(Ordering::SeqCst)
    );
}

#[test]
fn a_reuse_between_the_idx_delete_and_the_body_delete_keeps_the_body() {
    let mem = Arc::new(GitLike::default());
    let mut refs = hand_built(&mem, 12, 10);
    let start = t0();
    let lone = orphan(&mem, "reuse-0");
    let keys = [format!("packs/{lone}.idx"), format!("packs/{lone}.pack")];
    like_carrier(&mem).compact(&at(start)).unwrap(); // sights the orphan
    let late = mem.clone();
    let fired = Arc::new(AtomicBool::new(false));
    let hook: Hook = Box::new(move |op, key, after| {
        // Right after the idx files went: a push reuses the body that is still
        // there (its `put_new` leaves the body's oid unchanged), creates the idx
        // again and commits. The body's lease would still match its old oid.
        if op == "delete_leased"
            && after
            && key.ends_with(".idx")
            && !fired.swap(true, Ordering::SeqCst)
        {
            push_commits(&open(&late), "reuse", 1);
        }
        Ok(())
    });
    let rep = BucketTransport::build(Box::new(Wrapped::new(mem.bucket(), hook)), true)
        .unwrap()
        .compact(&at(start + 2 * DAY))
        .unwrap();
    for k in &keys {
        assert!(
            mem.bucket().exists(k).unwrap(),
            "{k} was deleted from under a live chain: {rep:?}"
        );
    }
    assert!(
        rep.notes
            .iter()
            .any(|n| n.contains("moved during pack deletion")),
        "{rep:?}"
    );
    refs.push(("reuse-0".to_string(), commit("reuse-0").0));
    assert_readable(&mem, &refs);
    // A rerun, seeing the pack live, leaves it and finishes the rest.
    like_carrier(&mem).compact(&at(start + 2 * DAY)).unwrap();
    assert_readable(&mem, &refs);
}

#[test]
fn a_pack_is_deleted_only_when_every_object_of_it_has_aged() {
    let mem = Arc::new(GitLike::default());
    let refs = hand_built(&mem, 12, 10);
    let start = t0();
    // The body alone (what an idx-first crash leaves), sighted by run 1.
    let (_, objects) = commit("lone");
    let (pack, idx) = scl_core::pack::build_pack(&objects).unwrap();
    let hash = hex::encode(blake3::hash(&pack).as_bytes());
    let b = mem.bucket();
    b.put_new(&pack_key(&hash), &pack).unwrap();
    like_carrier(&mem).compact(&at(start)).unwrap();
    // A fresh idx for the same hash appears afterwards.
    b.put_new(&idx_key(&hash), &idx).unwrap();
    let both = |mem: &Arc<GitLike>| {
        let b = mem.bucket();
        (
            b.exists(&pack_key(&hash)).unwrap(),
            b.exists(&idx_key(&hash)).unwrap(),
        )
    };
    // Two days on the body is old and the idx is not: neither goes.
    let r2 = like_carrier(&mem).compact(&at(start + 2 * DAY)).unwrap();
    assert_eq!(both(&mem), (true, true), "{r2:?}");
    assert_eq!(r2.packs_held_back, 1, "{r2:?}");
    // Once the idx has aged too, the pair goes.
    like_carrier(&mem).compact(&at(start + 4 * DAY)).unwrap();
    assert_eq!(both(&mem), (false, false));
    assert_readable(&mem, &refs);
}

#[test]
fn a_key_first_listed_in_a_replan_is_stamped_with_that_attempts_clock() {
    let mem = Arc::new(GitLike::default());
    hand_built(&mem, 12, 10);
    let late = mem.clone();
    let state = Arc::new(AtomicUsize::new(0));
    let hook_at = Arc::new(AtomicU64::new(0));
    let (st, at_secs) = (state.clone(), hook_at.clone());
    let hook: Hook = Box::new(move |op, key, after| {
        match (op, after, st.load(Ordering::SeqCst)) {
            ("list_tags", true, 0) => st.store(1, Ordering::SeqCst),
            // The first manifest read after the listing: a push lands, and a
            // while passes before the compactor looks again.
            ("get", false, 1) if key == "manifest" => {
                st.store(2, Ordering::SeqCst);
                push_commits(&open(&late), "late", 1);
                std::thread::sleep(Duration::from_millis(1100));
                at_secs.store(secs(SystemTime::now()), Ordering::SeqCst);
            }
            _ => {}
        }
        Ok(())
    });
    // The wall clock (no injected `now`), zero grace so the first attempt reaches
    // its manifest check and replans.
    BucketTransport::build(Box::new(Wrapped::new(mem.bucket(), hook)), true)
        .unwrap()
        .compact(&eager())
        .unwrap();
    assert_eq!(state.load(Ordering::SeqCst), 2, "the push never landed");
    // The late push's pack exists only from the second attempt on.
    let (_, objects) = commit("late-0");
    let (pack, _) = scl_core::pack::build_pack(&objects).unwrap();
    let hash = hex::encode(blake3::hash(&pack).as_bytes());
    let stamped = record_in(&mem)
        .first_seen(&pack_key(&hash))
        .expect("the late pack is tracked");
    assert!(
        stamped >= hook_at.load(Ordering::SeqCst),
        "first seen at {stamped}, but the replan began at {}",
        hook_at.load(Ordering::SeqCst)
    );
}

#[test]
fn a_retained_entry_that_changed_since_the_listing_keeps_the_packs_it_might_name() {
    let mem = Arc::new(GitLike::default());
    let refs = hand_built(&mem, 12, 10);
    let start = t0();
    let b = mem.bucket();
    let hidden = put_orphan(b.as_ref(), "hidden", |idx| idx);
    let keys = [
        format!("packs/{hidden}.idx"),
        format!("packs/{hidden}.pack"),
    ];
    like_carrier(&mem).compact(&at(start)).unwrap(); // sights the orphan
    let head = manifest(&mem).head_seq;
    let entry = |packs: Vec<String>| {
        LogEntry {
            seq: head + 1,
            parent_seq: head,
            packs,
            updates: vec![],
        }
        .encode()
    };
    let slot = log_key(head + 1);
    assert!(b.put_new(&slot, &entry(vec![])).unwrap());
    let Fetched::New { bytes, tag } = b.get(&slot, None).unwrap() else {
        panic!()
    };
    // A writer deletes that entry and creates it again naming the orphan. A
    // carrier that already read the first one keeps serving it from its cache.
    b.delete(&slot).unwrap();
    assert!(b.put_new(&slot, &entry(vec![hidden.clone()])).unwrap());
    let stale = Wrapped::new(mem.bucket(), quiet()).pin(&slot, bytes, tag);
    let rep = BucketTransport::build(Box::new(stale), true)
        .unwrap()
        .compact(&at(start + 2 * DAY))
        .unwrap();
    for k in &keys {
        assert!(b.exists(k).unwrap(), "{k} was deleted: {rep:?}");
    }
    assert!(
        rep.notes
            .iter()
            .any(|n| n.contains("packs kept") && n.contains("changed since the listing")),
        "{rep:?}"
    );
    // A fresh process reads the entry as it is and keeps the pack it names.
    like_carrier(&mem).compact(&at(start + 2 * DAY)).unwrap();
    for k in &keys {
        assert!(b.exists(k).unwrap(), "{k} was deleted by the rerun");
    }
    assert_readable(&mem, &refs);
}

#[test]
fn byte_counts_saturate_when_an_idx_declares_an_absurd_length() {
    let mem = Arc::new(GitLike::default());
    let refs = hand_built(&mem, 12, 10);
    let start = t0();
    let b = mem.bucket();
    // Two orphans whose idx puts every record at the end of the address space.
    let lies: Vec<String> = ["lie-1", "lie-2"]
        .iter()
        .map(|l| put_orphan(b.as_ref(), l, |idx| lying_idx(&idx, u64::MAX, 1)))
        .collect();
    like_carrier(&mem).compact(&at(start)).unwrap();
    // A sum of two such sizes overflows a u64 (a panic in a debug build).
    let dry = like_carrier(&mem)
        .compact(&CompactOptions {
            dry_run: true,
            ..at(start + 2 * DAY)
        })
        .unwrap();
    assert_eq!(
        (dry.packs_deleted, dry.bytes_deleted),
        (14, u64::MAX),
        "{dry:?}"
    );
    let real = like_carrier(&mem).compact(&at(start + 2 * DAY)).unwrap();
    assert_eq!(
        (real.packs_deleted, real.bytes_deleted),
        (14, u64::MAX),
        "{real:?}"
    );
    for h in &lies {
        assert!(!b.exists(&pack_key(h)).unwrap());
    }
    assert_readable(&mem, &refs);
}

#[test]
fn an_age_record_that_keeps_losing_its_cas_is_named_in_the_note() {
    let mem = Arc::new(GitLike::default());
    hand_built(&mem, 12, 10);
    let rival = mem.bucket();
    let n = Arc::new(AtomicUsize::new(0));
    // Every time the compactor is about to write the record, another compactor
    // gets in first with a record of its own.
    let hook: Hook = Box::new(move |op, key, after| {
        if op == "put_if_tag" && key == sightings::KEY && !after {
            let i = n.fetch_add(1, Ordering::SeqCst);
            let cur = match rival.get(sightings::KEY, None)? {
                Fetched::New { tag, .. } => Some(tag),
                _ => None,
            };
            let line = format!("1 {} packs/rival{i}.pack\n", "c".repeat(40));
            rival.put_if_tag(sightings::KEY, line.as_bytes(), cur.as_deref())?;
        }
        Ok(())
    });
    let rep = BucketTransport::build(Box::new(Wrapped::new(mem.bucket(), hook)), true)
        .unwrap()
        .compact(&eager())
        .unwrap();
    assert!(
        rep.notes
            .iter()
            .any(|n| n.contains("age record") && n.contains("compare-and-swap")),
        "{rep:?}"
    );
    assert!(!rep.notes.iter().any(|n| n.contains("manifest kept moving")));
    assert_eq!(
        (rep.logs_deleted, rep.checkpoints_deleted, rep.packs_deleted),
        (0, 0, 0),
        "{rep:?}"
    );
}

#[test]
fn the_byte_note_is_there_whenever_a_carrier_run_deletes_anything() {
    let mem = Arc::new(GitLike::default());
    hand_built(&mem, 12, 10);
    let start = t0();
    // No merging, so the second run deletes log entries only (no pack).
    let opts = |now| CompactOptions {
        small_pack_bytes: 0,
        ..at(now)
    };
    let first = like_carrier(&mem).compact(&opts(start)).unwrap();
    assert!(
        !first.notes.iter().any(|n| n.contains("byte counts")),
        "nothing was deleted, nothing was counted: {first:?}"
    );
    let second = like_carrier(&mem).compact(&opts(start + 2 * DAY)).unwrap();
    assert_eq!(
        (second.logs_deleted, second.packs_deleted),
        (10, 0),
        "{second:?}"
    );
    assert!(
        second
            .notes
            .iter()
            .any(|n| n.contains("byte counts are the pack bodies their idx declares")),
        "{second:?}"
    );
}
