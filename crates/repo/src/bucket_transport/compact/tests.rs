//! Compaction tests (#216, ADR-0057). Most run on an in-memory bucket (fast,
//! and lets a test fork a bucket or fake object ages); the full-run and the
//! concurrency tests use `DirBucket`, the real backend behind `sc+wal://`.

use super::super::CHECKPOINT_INTERVAL;
use super::*;
use crate::error::Error;
use crate::test_support::{note, watchdog, Status, Stop};
use crate::transport::Transport;
use crate::walfmt::{idx_key, RefUpdate};
use scl_core::Object;
use scl_objio::{Bucket, DirBucket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// In-memory `Bucket` with the same semantics as `DirBucket`.
#[derive(Default)]
struct MemBucket {
    map: Mutex<BTreeMap<String, (Vec<u8>, SystemTime)>>,
}

fn tag_of(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

impl MemBucket {
    fn fork(&self) -> Arc<MemBucket> {
        Arc::new(MemBucket {
            map: Mutex::new(self.map.lock().unwrap().clone()),
        })
    }
    /// Pretend `key` was written at `at`.
    fn touch(&self, key: &str, at: SystemTime) {
        self.map.lock().unwrap().get_mut(key).unwrap().1 = at;
    }
}

struct Shared(Arc<MemBucket>);
impl Bucket for Shared {
    fn get(&self, key: &str, cached: Option<&str>) -> scl_objio::Result<Fetched> {
        Ok(match self.0.map.lock().unwrap().get(key) {
            None => Fetched::Absent,
            Some((b, _)) if cached == Some(tag_of(b).as_str()) => Fetched::Unchanged,
            Some((b, _)) => Fetched::New {
                bytes: b.clone(),
                tag: tag_of(b),
            },
        })
    }
    fn put_new(&self, key: &str, bytes: &[u8]) -> scl_objio::Result<bool> {
        let mut m = self.0.map.lock().unwrap();
        if m.contains_key(key) {
            return Ok(false);
        }
        m.insert(key.into(), (bytes.to_vec(), SystemTime::now()));
        Ok(true)
    }
    fn put_if_tag(
        &self,
        key: &str,
        bytes: &[u8],
        expected: Option<&str>,
    ) -> scl_objio::Result<Option<String>> {
        let mut m = self.0.map.lock().unwrap();
        if m.get(key).map(|(b, _)| tag_of(b)).as_deref() != expected {
            return Ok(None);
        }
        m.insert(key.into(), (bytes.to_vec(), SystemTime::now()));
        Ok(Some(tag_of(bytes)))
    }
    fn list(&self, prefix: &str) -> scl_objio::Result<Vec<String>> {
        Ok(self.list_meta(prefix)?.into_iter().map(|m| m.key).collect())
    }
    fn list_meta(&self, prefix: &str) -> scl_objio::Result<Vec<ObjectMeta>> {
        Ok(self
            .0
            .map
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, (b, t))| ObjectMeta {
                key: k.clone(),
                size: b.len() as u64,
                modified: *t,
            })
            .collect())
    }
    fn exists(&self, key: &str) -> scl_objio::Result<bool> {
        Ok(self.0.map.lock().unwrap().contains_key(key))
    }
    fn delete(&self, key: &str) -> scl_objio::Result<()> {
        self.0.map.lock().unwrap().remove(key);
        Ok(())
    }
}

/// Where a test's bucket lives, so helpers work on either backend.
trait Store {
    fn bucket(&self) -> Box<dyn Bucket>;
}
impl Store for PathBuf {
    fn bucket(&self) -> Box<dyn Bucket> {
        Box::new(DirBucket::open(self).unwrap())
    }
}
impl Store for Arc<MemBucket> {
    fn bucket(&self) -> Box<dyn Bucket> {
        Box::new(Shared(self.clone()))
    }
}

/// Backdate every file under `dir` by an hour, as if the data had sat there.
fn age_files(dir: &std::path::Path) {
    let then = SystemTime::now() - Duration::from_secs(3600);
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        if e.path().is_dir() {
            age_files(&e.path());
        } else {
            std::fs::File::options()
                .write(true)
                .open(e.path())
                .unwrap()
                .set_modified(then)
                .unwrap();
        }
    }
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-bt-compact-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn open(s: &impl Store) -> BucketTransport {
    BucketTransport::from_bucket(s.bucket()).unwrap()
}

fn keys(s: &impl Store, prefix: &str) -> Vec<String> {
    s.bucket().list(prefix).unwrap()
}

fn manifest(s: &impl Store) -> Manifest {
    let Fetched::New { bytes, .. } = s.bucket().get("manifest", None).unwrap() else {
        panic!("no manifest")
    };
    Manifest::decode(&bytes).unwrap()
}

/// Options that merge everything and treat every object as old enough.
fn eager() -> CompactOptions {
    CompactOptions {
        prune_expire: Duration::ZERO,
        ..CompactOptions::default()
    }
}

/// A one-commit history: an empty tree shared by every commit plus a
/// snapshot distinguished by `label`. Returns (tip, objects).
fn commit(label: &str) -> (ObjectId, Vec<(ObjectId, Vec<u8>)>) {
    let tree = Object::Tree(scl_core::Tree::new(vec![]));
    let snap = Object::Snapshot(scl_core::Snapshot {
        root: tree.id(),
        parents: vec![],
        author: "t".into(),
        timestamp: 1,
        message: label.into(),
        secrets: Default::default(),
        protection: Default::default(),
    });
    (
        snap.id(),
        vec![(tree.id(), tree.encode()), (snap.id(), snap.encode())],
    )
}

/// Push `n` single-commit branches `<prefix>-<i>` through the real write path
/// (folds a checkpoint once the tail passes the interval).
fn push_commits(t: &BucketTransport, prefix: &str, n: u64) -> Vec<(String, ObjectId)> {
    (0..n)
        .map(|i| {
            let (tip, objects) = commit(&format!("{prefix}-{i}"));
            for (id, bytes) in &objects {
                t.put_object(id, bytes).unwrap();
            }
            let branch = format!("{prefix}-{i}");
            t.update_ref(&branch, &tip, None).unwrap();
            (branch, tip)
        })
        .collect()
}

/// Hand-build a WAL of `n` one-commit pushes with a checkpoint folded at `ck`
/// (0 = none): the shape real pushes leave, without their cost.
fn hand_built(s: &impl Store, n: u64, ck: u64) -> Vec<(String, ObjectId)> {
    let b = s.bucket();
    let (mut refs, mut packs) = (Vec::new(), Vec::new());
    for i in 1..=n {
        let (tip, objects) = commit(&format!("hb-{i}"));
        let (pack, idx) = scl_core::pack::build_pack(&objects).unwrap();
        let hash = hex::encode(blake3::hash(&pack).as_bytes());
        b.put_new(&pack_key(&hash), &pack).unwrap();
        b.put_new(&idx_key(&hash), &idx).unwrap();
        let entry = LogEntry {
            seq: i,
            parent_seq: i - 1,
            packs: vec![hash.clone()],
            updates: vec![RefUpdate {
                branch: format!("b-{i}"),
                old: None,
                new: tip,
            }],
        };
        b.put_new(&log_key(i), &entry.encode()).unwrap();
        refs.push((format!("b-{i}"), tip));
        packs.push(hash);
        if i == ck {
            let c = Checkpoint {
                seq: ck,
                refs: refs.clone(),
                packs: packs.clone(),
            };
            b.put_new(&checkpoint_key(ck), &c.encode()).unwrap();
        }
    }
    let m = Manifest {
        head_seq: n,
        checkpoint_seq: ck,
        head_branch: "b-1".into(),
    };
    b.put_if_tag("manifest", &m.encode(), None)
        .unwrap()
        .unwrap();
    refs.sort();
    refs
}

/// A cold-start reader sees exactly `expect` and can read every object both
/// singly and as one pack.
fn assert_readable(s: &impl Store, expect: &[(String, ObjectId)]) {
    let mut expect = expect.to_vec();
    expect.sort();
    let t = open(s);
    assert_eq!(t.list_refs().unwrap(), expect);
    for (_, id) in &expect {
        assert_eq!(ObjectId::of(&t.get_object(id).unwrap()), *id);
    }
    let tips: Vec<ObjectId> = expect.iter().map(|(_, id)| *id).collect();
    let mut out = Vec::new();
    t.get_pack(&tips, &[], None, &mut out).unwrap();
    // every tip's snapshot plus the one tree they share
    assert_eq!(
        scl_core::pack::parse_pack(&out).unwrap().len(),
        tips.len() + 1
    );
}

#[test]
fn the_in_memory_double_honors_the_bucket_contract() {
    scl_objio::contract_suite(&Shared(Arc::new(MemBucket::default())));
}

#[test]
fn merges_small_packs_and_sweeps_everything_behind_the_checkpoint() {
    let root = scratch("full");
    let t = open(&root);
    let refs = push_commits(&t, "w", 70);
    // 70 pushes folded a checkpoint at 65; 70 log entries, 70 packs.
    assert_eq!(manifest(&root).checkpoint_seq, 65);
    assert_eq!(keys(&root, "packs/").len(), 140);

    let rep = t.compact(&eager()).unwrap();
    assert_eq!((rep.packs_merged, rep.packs_created), (70, 1), "{rep:?}");
    assert_eq!(rep.checkpoint_seq, 71);
    assert_eq!(rep.cutoff, 71);
    assert_eq!((rep.logs_deleted, rep.checkpoints_deleted), (71, 1));
    assert_eq!(rep.packs_deleted, 70);

    let m = manifest(&root);
    assert_eq!((m.head_seq, m.checkpoint_seq), (71, 71));
    assert!(keys(&root, "log/").is_empty());
    assert_eq!(keys(&root, "checkpoints/").len(), 1);
    assert_eq!(keys(&root, "packs/").len(), 2, "one merged pack + idx");
    assert_readable(&root, &refs);

    // Idempotent: nothing left to do.
    let again = t.compact(&eager()).unwrap();
    assert_eq!(
        (
            again.packs_merged,
            again.logs_deleted,
            again.checkpoints_deleted,
            again.packs_deleted
        ),
        (0, 0, 0, 0),
        "{again:?}"
    );
    // And the remote still takes pushes.
    let mut all = refs;
    all.extend(push_commits(&t, "after", 3));
    assert_readable(&root, &all);
    std::fs::remove_dir_all(&root).unwrap();
    assert!(!root.exists());
}

#[test]
fn dry_run_reports_the_plan_and_writes_nothing() {
    let mem = Arc::new(MemBucket::default());
    let t = open(&mem);
    push_commits(&t, "w", 70);
    let before = mem.map.lock().unwrap().clone();
    let rep = t
        .compact(&CompactOptions {
            dry_run: true,
            ..eager()
        })
        .unwrap();
    assert!(rep.dry_run);
    assert_eq!((rep.packs_merged, rep.packs_created), (70, 1));
    assert!(rep.logs_deleted > 0 && rep.bytes_deleted > 0, "{rep:?}");
    assert!(!rep.notes.is_empty());
    assert!(
        *mem.map.lock().unwrap() == before,
        "dry run must not change the bucket"
    );
}

#[test]
fn nothing_is_deleted_inside_the_grace_window_and_everything_after_it() {
    let mem = Arc::new(MemBucket::default());
    let t = open(&mem);
    let refs = push_commits(&t, "w", 70);
    let rep = t.compact(&CompactOptions::default()).unwrap();
    // Phase 1 is additive and runs; the sweep keeps everything young.
    assert_eq!((rep.packs_merged, rep.packs_created), (70, 1));
    assert_eq!(
        (rep.logs_deleted, rep.checkpoints_deleted, rep.packs_deleted),
        (0, 0, 0)
    );
    assert_eq!(rep.packs_held_back, 70, "{rep:?}");
    assert_eq!(keys(&mem, "log/").len(), 71);
    assert_readable(&mem, &refs);

    // Two days later every object is past the window.
    let later = SystemTime::now() + Duration::from_secs(2 * 24 * 3600);
    let rep = t
        .compact(&CompactOptions {
            now: Some(later),
            ..CompactOptions::default()
        })
        .unwrap();
    assert_eq!(
        (rep.logs_deleted, rep.checkpoints_deleted, rep.packs_deleted),
        (71, 1, 70)
    );
    assert_readable(&mem, &refs);
}

#[test]
fn the_cutoff_is_the_newest_checkpoint_that_has_aged_not_the_newest_checkpoint() {
    // A busy remote folds every 64 pushes, so its newest checkpoint is rarely
    // old; an older one still sets the cutoff.
    let mem = Arc::new(MemBucket::default());
    let refs = hand_built(&mem, 12, 10);
    let b = mem.bucket();
    let Fetched::New { bytes, tag } = b.get("manifest", None).unwrap() else {
        panic!()
    };
    let mut m = Manifest::decode(&bytes).unwrap();
    let mut packs = Vec::new();
    for seq in 1..=12 {
        let Fetched::New { bytes, .. } = b.get(&log_key(seq), None).unwrap() else {
            panic!()
        };
        packs.extend(LogEntry::decode(&bytes).unwrap().packs);
    }
    let ck12 = Checkpoint {
        seq: 12,
        refs: refs.clone(),
        packs,
    };
    b.put_new(&checkpoint_key(12), &ck12.encode()).unwrap();
    m.checkpoint_seq = 12;
    b.put_if_tag("manifest", &m.encode(), Some(&tag))
        .unwrap()
        .unwrap();
    // Checkpoint 10 is two hours old, checkpoint 12 just landed; window 1h.
    let now = SystemTime::now();
    mem.touch(&checkpoint_key(10), now - Duration::from_secs(7200));

    let rep = open(&mem)
        .compact(&CompactOptions {
            small_pack_bytes: 0, // no merging: isolate the sweep
            prune_expire: Duration::from_secs(3600),
            now: Some(now),
            ..CompactOptions::default()
        })
        .unwrap();
    assert_eq!(rep.packs_merged, 0);
    assert_eq!(rep.cutoff, 10, "{rep:?}");
    assert_eq!((rep.logs_deleted, rep.checkpoints_deleted), (10, 0));
    assert_eq!(keys(&mem, "log/").len(), 2, "entries past the cutoff stay");
    assert_eq!(keys(&mem, "checkpoints/").len(), 2);
    assert_readable(&mem, &refs);
}

/// A bucket that fails every operation once a shared budget runs out, like a
/// process dying mid-compaction.
struct FailAfter {
    inner: Shared,
    left: Arc<AtomicI64>,
}
impl FailAfter {
    fn tick(&self) -> scl_objio::Result<()> {
        if self.left.fetch_sub(1, Ordering::SeqCst) <= 0 {
            Err(scl_objio::Error::Backend("injected failure".into()))
        } else {
            Ok(())
        }
    }
}
impl Bucket for FailAfter {
    fn get(&self, key: &str, tag: Option<&str>) -> scl_objio::Result<Fetched> {
        self.tick()?;
        self.inner.get(key, tag)
    }
    fn put_new(&self, key: &str, bytes: &[u8]) -> scl_objio::Result<bool> {
        self.tick()?;
        self.inner.put_new(key, bytes)
    }
    fn put_if_tag(
        &self,
        key: &str,
        bytes: &[u8],
        tag: Option<&str>,
    ) -> scl_objio::Result<Option<String>> {
        self.tick()?;
        self.inner.put_if_tag(key, bytes, tag)
    }
    fn list(&self, prefix: &str) -> scl_objio::Result<Vec<String>> {
        self.tick()?;
        self.inner.list(prefix)
    }
    fn list_meta(&self, prefix: &str) -> scl_objio::Result<Vec<ObjectMeta>> {
        self.tick()?;
        self.inner.list_meta(prefix)
    }
    fn exists(&self, key: &str) -> scl_objio::Result<bool> {
        self.tick()?;
        self.inner.exists(key)
    }
    fn delete(&self, key: &str) -> scl_objio::Result<()> {
        self.tick()?;
        self.inner.delete(key)
    }
}

#[test]
fn a_failure_at_every_operation_boundary_leaves_a_readable_bucket() {
    let template = Arc::new(MemBucket::default());
    let refs = hand_built(&template, 12, 10);
    let mut finished_at = None;
    for budget in 0..5000i64 {
        let work = template.fork();
        let left = Arc::new(AtomicI64::new(budget));
        let outcome = BucketTransport::from_bucket(Box::new(FailAfter {
            inner: Shared(work.clone()),
            left: left.clone(),
        }))
        .and_then(|t| t.compact(&eager()));

        // Whatever happened, a fresh reader still sees everything.
        assert_readable(&work, &refs);
        if outcome.is_ok() && left.load(Ordering::SeqCst) > 0 {
            finished_at = Some(budget);
            break;
        }
        // And a healthy rerun finishes the job.
        open(&work).compact(&eager()).unwrap();
        assert_readable(&work, &refs);
        assert_eq!(keys(&work, "packs/").len(), 2, "budget {budget}");
    }
    let n = finished_at.expect("compaction never completed within the budget");
    assert!(n > 20, "the loop should cross many boundaries, got {n}");
}

#[test]
fn readers_and_writers_stay_consistent_while_compaction_runs() {
    let root = scratch("concurrent");
    let seeded = hand_built(&root, 12, 10);
    age_files(&root); // the seed is old enough to sweep from the first run
    const WRITERS: usize = 3;
    const PER_WRITER: u64 = 20;
    const GRACE: Duration = Duration::from_millis(1500);
    let done = AtomicBool::new(false);
    let opts = CompactOptions {
        // Far longer than a writer's upload-to-commit gap even on a loaded
        // machine, short enough that sweeps really delete during the run.
        prune_expire: GRACE,
        ..CompactOptions::default()
    };
    let landed = Mutex::new(Vec::new());
    let deleted = std::sync::atomic::AtomicUsize::new(0);
    let finished = AtomicBool::new(false);
    let status = Status::default();
    let note = |who: String, what: String| note(&status, who, what);
    std::thread::scope(|s| {
        let _finish = Stop(&finished, true);
        let _stop = Stop(&done, false);
        watchdog(s, &finished, &status, Duration::from_secs(180));
        let note = &note;
        let writers: Vec<_> = (0..WRITERS)
            .map(|w| {
                let (root, landed, done) = (&root, &landed, &done);
                s.spawn(move || {
                    let _stop = Stop(done, false);
                    let t = open(root);
                    for i in 0..PER_WRITER {
                        let (tip, objects) = commit(&format!("writer-{w}-{i}"));
                        let branch = format!("writer-{w}-{i}");
                        let mut attempts = 0u32;
                        loop {
                            attempts += 1;
                            note(
                                format!("writer-{w}"),
                                format!("push {i}, attempt {attempts}"),
                            );
                            // A sweep only takes a pack older than GRACE, so a
                            // push that keeps losing its pack is not progressing.
                            assert!(attempts < 200, "writer {w}: push {i} never landed");
                            assert!(
                                !done.load(Ordering::SeqCst),
                                "writer {w}: another worker failed"
                            );
                            for (id, bytes) in &objects {
                                t.put_object(id, bytes).unwrap();
                            }
                            match t.update_ref(&branch, &tip, None) {
                                Ok(()) => break,
                                // The documented outcomes a rerun fixes: a pack
                                // swept before commit (the retry re-uploads), and
                                // 16 lost manifest CASes against the compactors.
                                Err(Error::Remote(m))
                                    if m.contains("removed from the bucket")
                                        || m.contains("manifest cas contention") => {}
                                Err(e) => panic!("writer {w}: {e}"),
                            }
                        }
                        landed.lock().unwrap().push((branch, tip));
                        std::thread::sleep(Duration::from_millis(80));
                    }
                })
            })
            .collect();
        let readers: Vec<_> = (0..3)
            .map(|r| {
                let (root, done, seeded) = (&root, &done, &seeded);
                s.spawn(move || {
                    let _stop = Stop(done, false);
                    let long_lived = open(root);
                    let mut seen = seeded.len();
                    let mut rounds = 0u32;
                    while !done.load(Ordering::SeqCst) || rounds < 3 {
                        rounds += 1;
                        note(format!("reader-{r}"), format!("round {rounds}"));
                        // alternate a long-lived (stale-view) reader and a cold start
                        let cold;
                        let t = if rounds.is_multiple_of(3) {
                            cold = open(root);
                            &cold
                        } else {
                            &long_lived
                        };
                        let refs = t.list_refs().unwrap_or_else(|e| panic!("reader {r}: {e}"));
                        assert!(refs.len() >= seen, "reader {r}: refs went backwards");
                        seen = refs.len();
                        for (_, id) in &refs {
                            let bytes = t
                                .get_object(id)
                                .unwrap_or_else(|e| panic!("reader {r}: get_object: {e}"));
                            assert_eq!(ObjectId::of(&bytes), *id);
                        }
                        let tips: Vec<ObjectId> = refs.iter().map(|(_, id)| *id).collect();
                        t.get_pack(&tips, &[], None, &mut Vec::new())
                            .unwrap_or_else(|e| panic!("reader {r}: get_pack: {e}"));
                        // Readers that never pause starve the writers' lock holders
                        // of filesystem time on a loaded machine.
                        std::thread::sleep(Duration::from_millis(5));
                    }
                })
            })
            .collect();
        // Two compactors at once: the ADR promises that is safe (just wasteful).
        let compactors: Vec<_> = (0..2)
            .map(|c| {
                let (root, done, opts, deleted) = (&root, &done, &opts, &deleted);
                s.spawn(move || {
                    let _stop = Stop(done, false);
                    let t = open(root);
                    let mut runs = 0u32;
                    while !done.load(Ordering::SeqCst) {
                        note(format!("compactor-{c}"), format!("run {runs}"));
                        match t.compact(opts) {
                            Ok(rep) => {
                                deleted.fetch_add(
                                    rep.logs_deleted + rep.checkpoints_deleted + rep.packs_deleted,
                                    Ordering::SeqCst,
                                );
                            }
                            // A rival's sweep took a pack this run was about to
                            // name; the guard fails the run instead of committing.
                            Err(Error::Remote(m)) if m.contains("removed from the bucket") => {}
                            Err(e) => panic!("compactor: {e}"),
                        }
                        runs += 1;
                        std::thread::sleep(Duration::from_millis(40));
                    }
                    runs
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        // Keep readers and the compactor running until everything the writers
        // produced has also aged past the window and been swept.
        std::thread::sleep(GRACE * 2);
        done.store(true, Ordering::SeqCst);
        for r in readers {
            r.join().unwrap();
        }
        for c in compactors {
            assert!(c.join().unwrap() > 2, "compactor barely ran");
        }
    });
    assert!(
        deleted.load(Ordering::SeqCst) > 0,
        "the sweep never deleted anything during the run, so this proved nothing"
    );
    let mut expect = seeded.clone();
    expect.extend(landed.into_inner().unwrap());
    // After the dust settles a zero-grace pass leaves a tight bucket.
    open(&root).compact(&eager()).unwrap();
    assert_readable(&root, &expect);
    assert_eq!(keys(&root, "packs/").len(), 2, "all packs merged into one");
    // Nothing at or below the head survives. A slot above it can: a rival
    // compactor's lost CAS leaves its claimed entry as debris, swept once a
    // checkpoint passes it.
    let head = manifest(&root).head_seq;
    assert!(keys(&root, "log/")
        .iter()
        .all(|k| seq_of(k).unwrap() > head));
    std::fs::remove_dir_all(&root).unwrap();
    assert!(!root.exists());
}

#[test]
fn a_reader_whose_view_was_swept_restarts_and_a_corrupt_bucket_still_fails() {
    let mem = Arc::new(MemBucket::default());
    let refs = hand_built(&mem, 12, 10);
    let reader = open(&mem);
    let (_, tip) = refs[0];
    assert!(reader.has_object(&tip).unwrap());
    // Compaction lands behind the reader's back and sweeps the old packs.
    open(&mem).compact(&eager()).unwrap();
    assert_eq!(keys(&mem, "packs/").len(), 2);
    // The reader's cached index points into a pack that no longer exists; the
    // fetch notices, re-reads the manifest and restarts on it.
    let bytes = reader.object_bytes(&tip).unwrap();
    assert_eq!(ObjectId::of(&bytes), tip);

    // With the manifest unchanged, a missing pack is corruption and fails.
    let pack = keys(&mem, "packs/")
        .into_iter()
        .find(|k| k.ends_with(".pack"))
        .unwrap();
    mem.bucket().delete(&pack).unwrap();
    let err = open(&mem).object_bytes(&tip).unwrap_err();
    assert!(format!("{err}").contains("body absent"), "{err}");
}

#[test]
fn a_cold_start_straddling_a_sweep_restarts_instead_of_failing() {
    // The reader read the manifest, then the checkpoint and log it names were
    // swept. Model it with a bucket that runs a compaction right after the
    // reader's first manifest read.
    struct SweepAfterManifest {
        inner: Shared,
        fired: Mutex<bool>,
    }
    impl Bucket for SweepAfterManifest {
        fn get(&self, key: &str, tag: Option<&str>) -> scl_objio::Result<Fetched> {
            let got = self.inner.get(key, tag)?;
            let mut fired = self.fired.lock().unwrap();
            if key == "manifest" && !*fired {
                *fired = true;
                drop(fired);
                BucketTransport::from_bucket(Box::new(Shared(self.inner.0.clone())))
                    .unwrap()
                    .compact(&eager())
                    .unwrap();
            }
            Ok(got)
        }
        fn put_new(&self, k: &str, b: &[u8]) -> scl_objio::Result<bool> {
            self.inner.put_new(k, b)
        }
        fn put_if_tag(
            &self,
            k: &str,
            b: &[u8],
            t: Option<&str>,
        ) -> scl_objio::Result<Option<String>> {
            self.inner.put_if_tag(k, b, t)
        }
        fn list(&self, p: &str) -> scl_objio::Result<Vec<String>> {
            self.inner.list(p)
        }
        fn list_meta(&self, p: &str) -> scl_objio::Result<Vec<ObjectMeta>> {
            self.inner.list_meta(p)
        }
        fn exists(&self, k: &str) -> scl_objio::Result<bool> {
            self.inner.exists(k)
        }
        fn delete(&self, k: &str) -> scl_objio::Result<()> {
            self.inner.delete(k)
        }
    }
    let mem = Arc::new(MemBucket::default());
    let refs = hand_built(&mem, 12, 10);
    let t = BucketTransport::from_bucket(Box::new(SweepAfterManifest {
        inner: Shared(mem.clone()),
        fired: Mutex::new(false),
    }))
    .expect("the cold start restarts on the new manifest");
    let mut expect = refs.clone();
    expect.sort();
    assert_eq!(t.list_refs().unwrap(), expect);
    assert_eq!(manifest(&mem).checkpoint_seq, 13, "the sweep really ran");
}

#[test]
fn a_push_whose_pack_was_swept_before_commit_fails_instead_of_corrupting() {
    let mem = Arc::new(MemBucket::default());
    let t = open(&mem);
    let (tip, objects) = commit("orphaned");
    let (pack, _) = scl_core::pack::build_pack(&objects).unwrap();
    t.put_pack(&mut std::io::Cursor::new(pack)).unwrap();
    // The sweep removes the not-yet-committed pack.
    for k in keys(&mem, "packs/") {
        mem.bucket().delete(&k).unwrap();
    }
    let err = t.update_ref("main", &tip, None).unwrap_err();
    assert!(
        format!("{err}").contains("removed from the bucket"),
        "{err}"
    );
    assert!(matches!(
        mem.bucket().get("manifest", None).unwrap(),
        Fetched::Absent
    ));
}

#[test]
fn a_remote_past_max_list_regains_folding_after_compaction() {
    let mem = Arc::new(MemBucket::default());
    // 66 commits in one real pack, plus MAX_LIST placeholder packs (valid,
    // empty), so the cumulative pack list is MAX_LIST + 1: one more than a
    // checkpoint can hold, which is what makes folding skip.
    const ENTRIES: u64 = 66;
    let commits: Vec<_> = (1..=ENTRIES).map(|i| commit(&format!("big-{i}"))).collect();
    let mut real: Vec<_> = commits.iter().flat_map(|(_, o)| o.clone()).collect();
    real.sort();
    real.dedup();
    let (rpack, ridx) = scl_core::pack::build_pack(&real).unwrap();
    let rhash = hex::encode(blake3::hash(&rpack).as_bytes());
    let (epack, eidx) = scl_core::pack::build_pack(&[]).unwrap();
    let fakes: Vec<String> = (0..MAX_LIST).map(|i| format!("fake-{i:06}")).collect();
    let b = mem.bucket();
    for h in &fakes {
        b.put_new(&pack_key(h), &epack).unwrap();
        b.put_new(&idx_key(h), &eidx).unwrap();
    }
    b.put_new(&pack_key(&rhash), &rpack).unwrap();
    b.put_new(&idx_key(&rhash), &ridx).unwrap();
    let chunk = fakes.len().div_ceil(ENTRIES as usize);
    let mut refs = Vec::new();
    for (i, (tip, _)) in commits.iter().enumerate() {
        let seq = i as u64 + 1;
        let mut packs: Vec<String> = fakes.chunks(chunk).nth(i).unwrap_or(&[]).to_vec();
        if i == 0 {
            packs.push(rhash.clone());
        }
        let entry = LogEntry {
            seq,
            parent_seq: seq - 1,
            packs,
            updates: vec![RefUpdate {
                branch: format!("b-{seq}"),
                old: None,
                new: *tip,
            }],
        };
        b.put_new(&log_key(seq), &entry.encode()).unwrap();
        refs.push((format!("b-{seq}"), *tip));
    }
    let m = Manifest {
        head_seq: ENTRIES,
        checkpoint_seq: 0,
        head_branch: "b-1".into(),
    };
    b.put_if_tag("manifest", &m.encode(), None)
        .unwrap()
        .unwrap();

    // Before: a push lands but its fold is skipped (over the cap).
    let t = open(&mem);
    refs.extend(push_commits(&t, "extra", 1));
    assert_eq!(
        manifest(&mem).checkpoint_seq,
        0,
        "fold should be skipped over the cap"
    );

    let rep = t.compact(&eager()).unwrap();
    // the fakes, the real pack and the extra push's pack
    assert_eq!(
        (rep.packs_merged, rep.packs_created),
        (MAX_LIST + 2, 1),
        "{rep:?}"
    );
    assert!(manifest(&mem).checkpoint_seq > 0);
    assert_eq!(rep.packs_deleted, MAX_LIST + 2);
    assert_readable(&mem, &refs);

    // After: ordinary pushes fold again.
    let ck_after = manifest(&mem).checkpoint_seq;
    refs.extend(push_commits(&t, "later", CHECKPOINT_INTERVAL + 2));
    assert!(
        manifest(&mem).checkpoint_seq > ck_after,
        "folding must resume once the pack list fits"
    );
    assert_readable(&mem, &refs);
}

#[test]
fn empty_bucket_and_single_pack_are_noops() {
    let mem = Arc::new(MemBucket::default());
    let t = open(&mem);
    let rep = t.compact(&eager()).unwrap();
    assert_eq!(rep.packs_merged, 0);
    assert!(!rep.notes.is_empty());
    // One pack is not a merge.
    let refs = push_commits(&t, "solo", 1);
    let rep = t.compact(&eager()).unwrap();
    assert_eq!((rep.packs_merged, rep.logs_deleted), (0, 0));
    assert_readable(&mem, &refs);
}

#[test]
fn a_first_push_that_died_before_the_manifest_leaves_orphans_the_sweep_ages_out() {
    let mem = Arc::new(MemBucket::default());
    let (_, objects) = commit("never committed");
    let (pack, idx) = scl_core::pack::build_pack(&objects).unwrap();
    let hash = hex::encode(blake3::hash(&pack).as_bytes());
    let b = mem.bucket();
    b.put_new(&pack_key(&hash), &pack).unwrap();
    b.put_new(&idx_key(&hash), &idx).unwrap();
    let t = open(&mem);
    // young: kept
    let rep = t.compact(&CompactOptions::default()).unwrap();
    assert_eq!((rep.packs_deleted, rep.packs_held_back), (0, 1));
    assert_eq!(keys(&mem, "packs/").len(), 2);
    // aged: swept, and the bucket is still a valid empty remote
    let rep = t.compact(&eager()).unwrap();
    assert_eq!(rep.packs_deleted, 1, "{rep:?}");
    assert!(keys(&mem, "packs/").is_empty());
    assert!(open(&mem).list_refs().unwrap().is_empty());
}

#[test]
fn a_manifest_that_moves_during_pack_deletion_stops_the_deletes() {
    // Wraps a bucket so the first pack delete is followed by a push by someone
    // else: the sweep must notice at its next look and keep the rest.
    struct PushOnFirstPackDelete {
        inner: Shared,
        freed: Arc<AtomicU64>,
        fired: Mutex<bool>,
    }
    impl Bucket for PushOnFirstPackDelete {
        fn get(&self, k: &str, t: Option<&str>) -> scl_objio::Result<Fetched> {
            self.inner.get(k, t)
        }
        fn put_new(&self, k: &str, b: &[u8]) -> scl_objio::Result<bool> {
            self.inner.put_new(k, b)
        }
        fn put_if_tag(
            &self,
            k: &str,
            b: &[u8],
            t: Option<&str>,
        ) -> scl_objio::Result<Option<String>> {
            self.inner.put_if_tag(k, b, t)
        }
        fn list(&self, p: &str) -> scl_objio::Result<Vec<String>> {
            self.inner.list(p)
        }
        fn list_meta(&self, p: &str) -> scl_objio::Result<Vec<ObjectMeta>> {
            self.inner.list_meta(p)
        }
        fn exists(&self, k: &str) -> scl_objio::Result<bool> {
            self.inner.exists(k)
        }
        fn delete(&self, k: &str) -> scl_objio::Result<()> {
            if let Fetched::New { bytes, .. } = self.inner.get(k, None)? {
                self.freed.fetch_add(bytes.len() as u64, Ordering::SeqCst);
            }
            self.inner.delete(k)?;
            let mut fired = self.fired.lock().unwrap();
            if k.starts_with("packs/") && !*fired {
                *fired = true;
                drop(fired);
                push_commits(&open(&self.inner.0), "late", 1);
            }
            Ok(())
        }
    }
    let mem = Arc::new(MemBucket::default());
    let refs = push_commits(&open(&mem), "w", 70);
    let freed = Arc::new(AtomicU64::new(0));
    let t = BucketTransport::from_bucket(Box::new(PushOnFirstPackDelete {
        inner: Shared(mem.clone()),
        fired: Mutex::new(false),
        freed: freed.clone(),
    }))
    .unwrap();
    let rep = t.compact(&eager()).unwrap();
    assert!(
        rep.notes
            .iter()
            .any(|n| n.contains("moved during pack deletion")),
        "{rep:?}"
    );
    assert!(rep.packs_deleted < 70, "{rep:?}");
    // The packs kept after the manifest moved are not counted as reclaimed
    // (#263): the report equals what really left the bucket.
    assert_eq!(rep.bytes_deleted, freed.load(Ordering::SeqCst), "{rep:?}");
    // some old packs were kept, the bucket is readable, and a rerun finishes
    assert!(keys(&mem, "packs/").len() > 4);
    let mut all = refs;
    all.push(("late-0".to_string(), commit("late-0").0));
    assert_readable(&mem, &all);
    open(&mem).compact(&eager()).unwrap();
    assert_eq!(keys(&mem, "packs/").len(), 2);
    assert_readable(&mem, &all);
}

/// A branch whose tip carries one `len`-byte blob of `fill`: a pack that is a
/// few hundred bytes on disk but `len` decoded.
fn push_compressible(t: &BucketTransport, branch: &str, fill: u8, len: usize) {
    let blob = Object::blob(vec![fill; len]);
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
        message: branch.into(),
        secrets: Default::default(),
        protection: Default::default(),
    });
    for o in [&blob, &tree, &snap] {
        t.put_object(&o.id(), &o.encode()).unwrap();
    }
    t.update_ref(branch, &snap.id(), None).unwrap();
}

#[test]
fn candidates_that_are_each_large_once_decoded_are_not_merged_one_by_one() {
    let mem = Arc::new(MemBucket::default());
    let t = open(&mem);
    // Tiny on disk, so both are candidates and share one group; each decodes
    // past the spill limit (4 x group_bytes) on its own.
    let opts = CompactOptions {
        group_bytes: 64 << 10,
        ..eager()
    };
    push_compressible(&t, "big-0", 1, 1 << 20);
    push_compressible(&t, "big-1", 2, 1 << 20);
    let before = manifest(&mem);
    // The dry run reports what the real run will do: nothing.
    let dry = t
        .compact(&CompactOptions {
            dry_run: true,
            ..opts.clone()
        })
        .unwrap();
    assert_eq!((dry.packs_merged, dry.packs_created), (0, 0), "{dry:?}");
    let rep = t.compact(&opts).unwrap();
    assert_eq!((rep.packs_merged, rep.packs_created), (0, 0), "{rep:?}");
    assert!(
        rep.notes
            .iter()
            .any(|n| n.contains("reduce the pack count")),
        "{rep:?}"
    );
    assert_eq!(manifest(&mem), before, "no empty log entry or checkpoint");
    assert_eq!(keys(&mem, "packs/").len(), 4);

    // Small packs beside them still merge, into fewer packs than they were.
    push_commits(&t, "s", 2);
    let rep = t.compact(&opts).unwrap();
    assert!(rep.packs_merged >= 2, "{rep:?}");
    assert!(rep.packs_created < rep.packs_merged, "{rep:?}");
    let t2 = open(&mem);
    for b in ["big-0", "big-1", "s-0", "s-1"] {
        let tip = t2
            .list_refs()
            .unwrap()
            .into_iter()
            .find(|(n, _)| n == b)
            .unwrap()
            .1;
        t2.get_object(&tip).unwrap();
    }
}
