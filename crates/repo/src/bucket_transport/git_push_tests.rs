//! What a push to a bucket costs in round trips (ADR-0060 addendum): the pack
//! and its idx go up in one batch, the pre-commit presence check is one call,
//! the view after a won manifest CAS is built from the manifest just written,
//! and an empty remote is probed once, not once per object. Most tests count
//! calls on a recording wrapper over a `DirBucket`; the last one counts the real
//! `git` calls of a push to a `sc+git::` carrier through a logging shim.

use super::*;
use crate::repo::Repo;
use scl_objio::{DirBucket, ObjectMeta};
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Every bucket call, in order, as `name` or `name:detail`.
#[derive(Clone, Default)]
struct Calls(Arc<Mutex<Vec<String>>>);

impl Calls {
    fn note(&self, s: impl Into<String>) {
        self.0.lock().unwrap().push(s.into());
    }
    fn count(&self, prefix: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.starts_with(prefix))
            .count()
    }
}

/// Forwards every call to `inner` and records it. The batch methods are
/// forwarded as batches (not split into singles), so what is recorded is what
/// the transport asked for.
struct Counting {
    inner: Box<dyn Bucket>,
    calls: Calls,
    /// Fail the next read of a log entry once (armed by a won manifest CAS).
    fail_log_read_after_cas: Arc<AtomicBool>,
    fail_log_read: Arc<AtomicBool>,
}

impl Counting {
    fn over(root: &std::path::Path) -> (Counting, Calls) {
        let calls = Calls::default();
        let c = Counting {
            inner: Box::new(DirBucket::open(root).unwrap()),
            calls: calls.clone(),
            fail_log_read_after_cas: Arc::new(AtomicBool::new(false)),
            fail_log_read: Arc::new(AtomicBool::new(false)),
        };
        (c, calls)
    }
}

impl Bucket for Counting {
    fn get(&self, key: &str, tag: Option<&str>) -> scl_objio::Result<Fetched> {
        self.calls.note(format!("get:{key}"));
        if key.starts_with("log/") && self.fail_log_read.swap(false, Ordering::SeqCst) {
            return Err(scl_objio::Error::Backend("injected read failure".into()));
        }
        self.inner.get(key, tag)
    }
    fn put_new(&self, key: &str, bytes: &[u8]) -> scl_objio::Result<bool> {
        self.calls.note(format!("put_new:{key}"));
        self.inner.put_new(key, bytes)
    }
    fn put_if_tag(
        &self,
        key: &str,
        bytes: &[u8],
        expected: Option<&str>,
    ) -> scl_objio::Result<Option<String>> {
        self.calls.note(format!("put_if_tag:{key}"));
        let r = self.inner.put_if_tag(key, bytes, expected)?;
        if r.is_some() && self.fail_log_read_after_cas.load(Ordering::SeqCst) {
            self.fail_log_read.store(true, Ordering::SeqCst);
        }
        Ok(r)
    }
    fn list(&self, prefix: &str) -> scl_objio::Result<Vec<String>> {
        self.inner.list(prefix)
    }
    fn list_meta(&self, prefix: &str) -> scl_objio::Result<Vec<ObjectMeta>> {
        self.inner.list_meta(prefix)
    }
    fn exists(&self, key: &str) -> scl_objio::Result<bool> {
        self.calls.note(format!("exists:{key}"));
        self.inner.exists(key)
    }
    fn delete(&self, key: &str) -> scl_objio::Result<()> {
        self.inner.delete(key)
    }
    fn put_new_batch(&self, items: &[(&str, &[u8])]) -> scl_objio::Result<Vec<bool>> {
        self.calls.note(format!("put_new_batch:{}", items.len()));
        self.inner.put_new_batch(items)
    }
    fn exists_batch(&self, keys: &[&str]) -> scl_objio::Result<Vec<bool>> {
        self.calls.note(format!("exists_batch:{}", keys.len()));
        self.inner.exists_batch(keys)
    }
}

type Objects = Vec<(ObjectId, Vec<u8>)>;

/// `n` commits on one file, each with a different content: per commit its tip
/// and every object reachable from it.
fn history(tag: &str, n: usize) -> Vec<(ObjectId, Objects)> {
    let root = std::env::temp_dir().join(format!("scl-bt-push-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let repo = Repo::init(&root).unwrap();
    let mut out = Vec::new();
    for i in 0..n {
        std::fs::write(root.join("f.txt"), format!("content {tag} {i}")).unwrap();
        let tip = repo.commit("t", &format!("c{i}")).unwrap();
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let objects = crate::reachable::reachable_objects(&mut *store, &[tip])
            .unwrap()
            .into_iter()
            .map(|id| (id, store.get(&id).unwrap().encode()))
            .collect();
        out.push((tip, objects));
    }
    drop(repo);
    std::fs::remove_dir_all(&root).unwrap();
    out
}

/// Exactly what `Repo::push` does against a transport: read the refs, probe
/// each object, send the missing ones as one pack, move the ref.
fn push(t: &BucketTransport, tip: ObjectId, objects: &Objects) -> Result<()> {
    let expected = t
        .list_refs()?
        .into_iter()
        .find(|(b, _)| b == "main")
        .map(|(_, id)| id);
    let mut missing = Vec::new();
    for (id, bytes) in objects {
        if !t.has_object(id)? {
            missing.push((*id, bytes.clone()));
        }
    }
    if !missing.is_empty() {
        let (pack, _) = scl_core::pack::build_pack(&missing)?;
        t.put_pack(&mut Cursor::new(pack))?;
    }
    t.update_ref("main", &tip, expected.as_ref())
}

fn bucket_root(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-bt-pushbk-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn cleanup(root: &std::path::Path) {
    std::fs::remove_dir_all(root).unwrap();
    assert!(!root.exists());
}

#[test]
fn a_first_push_costs_one_batch_per_step_and_probes_the_empty_remote_per_reader_not_per_object() {
    let root = bucket_root("first");
    let (c, calls) = Counting::over(&root);
    let t = BucketTransport::from_bucket(Box::new(c)).unwrap();
    let h = history("first", 1);
    let (tip, objects) = &h[0];
    assert!(objects.len() >= 3, "a commit, a tree and a blob at least");
    push(&t, *tip, objects).unwrap();
    // pack + idx in one batch; the pre-commit check is one call over both keys
    assert_eq!(calls.count("put_new_batch"), 1);
    assert_eq!(calls.count("put_new_batch:2"), 1);
    assert_eq!(calls.count("put_new:pack"), 0);
    assert_eq!(calls.count("exists_batch"), 1);
    assert_eq!(calls.count("exists_batch:2"), 1);
    assert_eq!(calls.count("exists:"), 0);
    // the manifest is read at open, by list_refs and by update_ref; the
    // per-object probes after list_refs and the read after the won CAS add none
    assert_eq!(calls.count("get:manifest"), 3);
    // and the push is on the remote
    let r = BucketTransport::from_bucket(Box::new(DirBucket::open(&root).unwrap())).unwrap();
    assert_eq!(r.list_refs().unwrap(), vec![("main".to_string(), *tip)]);
    drop((t, r));
    cleanup(&root);
}

#[test]
fn a_second_push_on_the_same_transport_succeeds_on_the_view_the_first_installed() {
    let root = bucket_root("second");
    let (c, calls) = Counting::over(&root);
    let t = BucketTransport::from_bucket(Box::new(c)).unwrap();
    let h = history("second", 2);
    let (tip1, objects1) = &h[0];
    let (tip2, objects2) = &h[1];
    push(&t, *tip1, objects1).unwrap();
    let after_first = calls.count("get:manifest");
    // the view is the one the commit produced: the tag is the bucket's
    let tag = |t: &BucketTransport| t.view.borrow().as_ref().map(|v| v.tag.clone());
    let current = match DirBucket::open(&root)
        .unwrap()
        .get("manifest", None)
        .unwrap()
    {
        Fetched::New { tag, .. } => tag,
        _ => panic!("manifest should exist"),
    };
    assert_eq!(tag(&t), Some(current));
    // a ref move with `Some(old)` straight after, with no new read in between
    let missing: Objects = objects2
        .iter()
        .filter(|(id, _)| !objects1.iter().any(|(o, _)| o == id))
        .cloned()
        .collect();
    t.put_pack(&mut Cursor::new(
        scl_core::pack::build_pack(&missing).unwrap().0,
    ))
    .unwrap();
    t.update_ref("main", tip2, Some(tip1)).unwrap();
    assert_eq!(
        calls.count("get:manifest"),
        after_first + 1,
        "one read per update_ref"
    );
    assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), *tip2)]);
    drop(t);
    cleanup(&root);
}

#[test]
fn if_the_view_cannot_be_built_from_the_manifest_just_written_it_is_read_back() {
    let root = bucket_root("fallback");
    let (c, calls) = Counting::over(&root);
    c.fail_log_read_after_cas.store(true, Ordering::SeqCst);
    let t = BucketTransport::from_bucket(Box::new(c)).unwrap();
    let h = history("fallback", 1);
    let (tip, objects) = &h[0];
    push(&t, *tip, objects).unwrap();
    // the commit landed, the first build failed, the re-read built the view
    assert_eq!(calls.count("get:manifest"), 4);
    assert_eq!(t.view.borrow().as_ref().map(|v| v.refs.len()), Some(1));
    assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), *tip)]);
    drop(t);
    cleanup(&root);
}

#[test]
fn a_pack_that_is_already_in_the_bucket_is_still_a_successful_upload() {
    let root = bucket_root("present");
    let h = history("present", 1);
    let (tip, objects) = &h[0];
    // an earlier attempt uploaded the pack and idx but never moved the ref
    let a = BucketTransport::from_bucket(Box::new(DirBucket::open(&root).unwrap())).unwrap();
    a.put_pack(&mut Cursor::new(
        scl_core::pack::build_pack(objects).unwrap().0,
    ))
    .unwrap();
    let (c, calls) = Counting::over(&root);
    let t = BucketTransport::from_bucket(Box::new(c)).unwrap();
    // the objects are not on the chain yet, so the push sends them again
    push(&t, *tip, objects).unwrap();
    assert_eq!(calls.count("put_new_batch:2"), 1);
    assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), *tip)]);
    drop((a, t));
    cleanup(&root);
}

#[test]
fn the_pre_commit_check_covers_every_pending_pack_in_one_call_and_names_the_missing_one() {
    let root = bucket_root("ensure");
    let (c, calls) = Counting::over(&root);
    let t = BucketTransport::from_bucket(Box::new(c)).unwrap();
    let h = history("ensure", 2);
    let (tip2, objects2) = &h[1];
    let (_, objects1) = &h[0];
    t.put_pack(&mut Cursor::new(
        scl_core::pack::build_pack(objects1).unwrap().0,
    ))
    .unwrap();
    let missing: Objects = objects2
        .iter()
        .filter(|(id, _)| !objects1.iter().any(|(o, _)| o == id))
        .cloned()
        .collect();
    t.put_pack(&mut Cursor::new(
        scl_core::pack::build_pack(&missing).unwrap().0,
    ))
    .unwrap();
    let pending = t.pending_packs.borrow().clone();
    assert_eq!(pending.len(), 2);
    // a compaction sweeps the second pack's body before the commit
    DirBucket::open(&root)
        .unwrap()
        .delete(&pack_key(&pending[1]))
        .unwrap();
    let e = t.update_ref("main", tip2, None).unwrap_err().to_string();
    assert!(
        e.contains(&pending[1]) && e.contains("retry the push"),
        "{e}"
    );
    assert!(!e.contains(&pending[0]), "named the wrong pack: {e}");
    assert_eq!(
        calls.count("exists_batch:4"),
        1,
        "both packs, both keys, one call"
    );
    assert_eq!(calls.count("exists_batch"), 1);
    drop(t);
    cleanup(&root);
}

/// Another writer publishes the first manifest while this transport still
/// remembers the remote as empty.
fn empty_then_published(
    tag: &str,
) -> (
    std::path::PathBuf,
    BucketTransport,
    Calls,
    ObjectId,
    ObjectId,
) {
    let root = bucket_root(tag);
    let (c, calls) = Counting::over(&root);
    let t1 = BucketTransport::from_bucket(Box::new(c)).unwrap();
    let h = history(tag, 1);
    let t2 = BucketTransport::from_bucket(Box::new(DirBucket::open(&root).unwrap())).unwrap();
    push(&t2, h[0].0, &h[0].1).unwrap();
    (root, t1, calls, h[0].0, h[0].1[0].0)
}

#[test]
fn only_the_per_object_probe_trusts_a_recent_empty_manifest() {
    // has_object answers from the memo and asks the bucket nothing
    let root = bucket_root("memo");
    // Built first, so the probes below run well inside the memo window.
    let h = history("memo", 1);
    let (c, calls) = Counting::over(&root);
    let t = BucketTransport::from_bucket(Box::new(c)).unwrap();
    let before = calls.count("get:manifest");
    assert_eq!(before, 1, "opened on an empty remote");
    for (id, _) in &h[0].1 {
        assert!(!t.has_object(id).unwrap());
    }
    assert_eq!(calls.count("get:manifest"), before);
    // an older memo is probed again
    t.absent_at
        .set(Some(Instant::now().checked_sub(ABSENT_MEMO * 2).unwrap()));
    assert!(!t.has_object(&h[0].1[0].0).unwrap());
    assert_eq!(calls.count("get:manifest"), before + 1);
    drop(t);
    cleanup(&root);

    // list_refs, head_branch and update_ref never use it
    let (root, t1, calls, tip, _) = empty_then_published("memo-list");
    let before = calls.count("get:manifest");
    assert_eq!(t1.list_refs().unwrap(), vec![("main".to_string(), tip)]);
    assert_eq!(calls.count("get:manifest"), before + 1);
    drop(t1);
    cleanup(&root);

    let (root, t1, _, _, _) = empty_then_published("memo-head");
    assert_eq!(t1.head_branch().unwrap(), "main");
    drop(t1);
    cleanup(&root);

    // update_ref sees the published manifest at once: with a stale "empty" it
    // would try to create the branch instead of refusing the move
    let (root, t1, _, tip, _) = empty_then_published("memo-update");
    let h = history("memo-update-other", 1);
    t1.put_pack(&mut Cursor::new(
        scl_core::pack::build_pack(&h[0].1).unwrap().0,
    ))
    .unwrap();
    let e = t1.update_ref("main", &h[0].0, None).unwrap_err();
    assert!(matches!(e, Error::NonFastForward), "{e}");
    assert_eq!(t1.list_refs().unwrap(), vec![("main".to_string(), tip)]);
    drop(t1);
    cleanup(&root);
}

#[test]
fn the_empty_memo_is_cleared_by_any_other_read_and_by_a_won_cas() {
    let (root, t1, _, _, id) = empty_then_published("memo-clear");
    assert!(t1.absent_at.get().is_some(), "set by the read at open");
    // Restart the window: building and publishing the history took time.
    t1.absent_at.set(Some(Instant::now()));
    // inside the window the probe is answered from the memo
    assert!(
        !t1.has_object(&id).unwrap(),
        "stale by design, for one window"
    );
    // any other read result clears it, and then the probe asks again
    t1.list_refs().unwrap();
    assert!(t1.absent_at.get().is_none());
    assert!(t1.has_object(&id).unwrap());
    drop(t1);
    cleanup(&root);

    // a won CAS clears it too
    let root = bucket_root("memo-cas");
    let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&root).unwrap())).unwrap();
    assert!(t.absent_at.get().is_some());
    let h = history("memo-cas", 1);
    push(&t, h[0].0, &h[0].1).unwrap();
    assert!(t.absent_at.get().is_none());
    drop(t);
    cleanup(&root);
}

#[cfg(unix)]
mod carrier {
    use super::*;
    use scl_objio::GitBucket;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    fn have_git() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// A bare hub plus a `git` shim that logs the subcommand of every call.
    struct Carrier {
        dir: PathBuf,
        url: String,
        shim: String,
        log: PathBuf,
    }

    impl Carrier {
        fn new(tag: &str) -> Carrier {
            let dir = bucket_root(&format!("carrier-{tag}"));
            std::fs::create_dir_all(&dir).unwrap();
            let bare = dir.join("hub.git");
            let ok = Command::new("git")
                .args(["init", "--bare", "-q", bare.to_str().unwrap()])
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .status()
                .unwrap();
            assert!(ok.success());
            let log = dir.join("calls.log");
            let shim = dir.join("git-shim.sh");
            std::fs::write(
                &shim,
                format!(
                    "#!/bin/sh\ns=; k=0; for x in \"$@\"; do if [ $k = 1 ]; then k=0; continue; fi; if [ \"$x\" = -c ]; then k=1; continue; fi; s=$x; break; done\necho \"$s\" >> {}\nexec git \"$@\"\n",
                    log.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
            Carrier {
                url: format!("file://{}", bare.display()),
                shim: shim.to_str().unwrap().to_string(),
                dir,
                log,
            }
        }

        /// Network `git` calls made so far (push, fetch, ls-remote).
        fn network_calls(&self) -> Vec<String> {
            std::fs::read_to_string(&self.log)
                .unwrap_or_default()
                .lines()
                .filter(|l| matches!(*l, "push" | "fetch" | "ls-remote"))
                .map(String::from)
                .collect()
        }

        /// What `sc push` does: open the carrier (one manifest read), then push.
        fn push(&self, tip: ObjectId, objects: &Objects) -> Vec<String> {
            let before = self.network_calls().len();
            let b = GitBucket::open_with_program(&self.url, &self.shim).unwrap();
            let t = BucketTransport::build(Box::new(b), true).unwrap();
            push(&t, tip, objects).unwrap();
            drop(t);
            self.network_calls().split_off(before)
        }
    }

    impl Drop for Carrier {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_push_to_a_git_carrier_costs_a_bounded_number_of_network_calls() {
        if !have_git() {
            eprintln!("git not available; skipping");
            return;
        }
        let c = Carrier::new("counts");
        let h = history("counts", 2);
        let first = c.push(h[0].0, &h[0].1);
        let second = c.push(h[1].0, &h[1].1);
        // Each probe of the still-empty remote is a failed fetch plus the
        // ls-remote that tells "absent" from "failed": the read at open,
        // list_refs and update_ref (the per-object probes are free). Then the
        // pack and idx in one push, the log entry, one existence check of pack
        // and idx, the manifest. Before this change the same push cost 19.
        assert_eq!(
            first,
            [
                "fetch",
                "ls-remote",
                "fetch",
                "ls-remote",
                "push",
                "fetch",
                "ls-remote",
                "push",
                "ls-remote",
                "push"
            ]
        );
        // The manifest, the log family and the idx family read cold, the pack
        // and idx in one push, the old pack body the ref rule reads, the log
        // entry, one existence check, the manifest. Before this change: 11.
        assert_eq!(
            second,
            [
                "fetch",
                "fetch",
                "fetch",
                "push",
                "fetch",
                "push",
                "ls-remote",
                "push"
            ]
        );
    }
}
