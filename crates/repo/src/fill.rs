//! By-id gap filling for lazy partial clones (P37, ADR-0047).
//!
//! A partial clone (ADR-0037) never fetched anything outside its filter. A
//! clone marked lazy (`.sc/promisor-lazy`) may ask its promisor remote for
//! exactly the trees and blobs one read needs, by id, one tree depth per round
//! trip. This module is the ONLY place that dials the remote after clone:
//! `Store::get` stays network-free, so gc, verify, materialize and the desktop
//! read model can never block on the network.
//!
//! Filling only ADDS objects the filter did not cover. The promisor filter is
//! unchanged, so push, gc and verify (all filter-scoped walks) behave exactly
//! as they did before the fill; they simply find a few extra present objects.

use std::collections::BTreeSet;

use scl_core::{EntryKind, Object, ObjectId};

use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::stdio_transport::open_transport;
use crate::transport::{ingest_pack_file_checked, TempPackGuard, Transport};

/// What a fill cost: network round trips and objects ingested. Lets tests and
/// the demo assert that a read fetched only what it needed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FillStats {
    /// `GetObjects` round trips made.
    pub requests: usize,
    /// Objects written to the local store.
    pub objects: usize,
}

impl Repo {
    /// Fetch `ids` from `transport` by id, verify them, and write them to the
    /// local store. One round trip; `ids` must not exceed
    /// [`crate::wire::MAX_GET_OBJECTS_IDS`].
    ///
    /// Every returned object is hash-verified before any is written, and the
    /// reply must partition the request exactly: nothing unrequested, nothing
    /// both sent and refused, nothing silently omitted. An id the remote
    /// reports as not sent is a terminal `NotFound` (after the objects it did
    /// send are ingested: they are immutable, so keeping them is harmless and
    /// a retry resumes from current presence).
    pub(crate) fn fetch_by_id_from(
        &self,
        transport: &dyn Transport,
        ids: &[ObjectId],
    ) -> Result<usize> {
        let requested: BTreeSet<ObjectId> = ids.iter().copied().collect();
        let guard = TempPackGuard::new(&self.layout)?;
        let not_sent = {
            let mut f = std::fs::File::create(guard.path())?;
            transport.get_objects(ids, &mut f)?
        };
        let not_sent_set: BTreeSet<ObjectId> = not_sent.iter().copied().collect();

        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let ingested = ingest_pack_file_checked(
            &self.layout,
            &mut store,
            guard.path(),
            Some(requested.len()),
            |found| {
                if let Some(id) = found.difference(&requested).next() {
                    return Err(Error::Protocol(format!(
                        "remote sent unrequested object {id}"
                    )));
                }
                if let Some(id) = not_sent_set.difference(&requested).next() {
                    return Err(Error::Protocol(format!(
                        "remote listed unrequested object {id} as not sent"
                    )));
                }
                if let Some(id) = found.intersection(&not_sent_set).next() {
                    return Err(Error::Protocol(format!(
                        "remote both sent and refused object {id}"
                    )));
                }
                if let Some(id) = requested
                    .iter()
                    .find(|id| !found.contains(id) && !not_sent_set.contains(id))
                {
                    return Err(Error::Protocol(format!(
                        "remote neither sent nor refused object {id}"
                    )));
                }
                Ok(())
            },
        )?;
        if let Some(id) = not_sent.first() {
            return Err(Error::Core(scl_core::Error::NotFound(*id)));
        }
        Ok(ingested.len())
    }

    /// The bytes of the file at `path` as of `refname`'s tip (`sc cat
    /// <ref>:<path>`). On a lazy partial clone, trees and the blob missing
    /// locally are fetched by id on the way down (one round trip per tree
    /// depth plus one for the blob); otherwise a missing object is the usual
    /// gap error pointing at `sc backfill`.
    ///
    /// Refuses private branches and protected paths: this phase prints
    /// public plaintext only.
    pub fn cat_at(&self, refname: &str, path: &str) -> Result<Vec<u8>> {
        Ok(self.cat_at_with_stats(refname, path)?.0)
    }

    /// [`Repo::cat_at`], also reporting what the fill cost.
    pub fn cat_at_with_stats(&self, refname: &str, path: &str) -> Result<(Vec<u8>, FillStats)> {
        self.cat_at_impl(refname, path, crate::promisor::offline())
    }

    /// `offline` is a parameter so tests can exercise the `SC_OFFLINE` path
    /// without mutating the process environment.
    fn cat_at_impl(
        &self,
        refname: &str,
        path: &str,
        offline: bool,
    ) -> Result<(Vec<u8>, FillStats)> {
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        if comps.is_empty() {
            return Err(Error::InvalidArgument("sc cat needs a file path".into()));
        }
        let tip = crate::refs::resolve_tip(&self.layout, refname)?
            .ok_or_else(|| Error::InvalidArgument(format!("unknown ref '{refname}'")))?;
        let root = {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            match store.get(&tip)? {
                Object::Snapshot(s) => s.root,
                Object::Manifest(_) => return Err(Error::PrivateUnsupported("sc cat".into())),
                _ => {
                    return Err(Error::InvalidArgument(format!(
                        "'{refname}' does not name a snapshot"
                    )))
                }
            }
        };

        let mut filler = Filler::new(self, offline)?;
        let mut cur = root;
        for (i, comp) in comps.iter().enumerate() {
            filler.ensure_present(&cur, path)?;
            let entry = {
                let store_arc = self.vfs.store();
                let mut store = store_arc.lock().unwrap();
                let tree = store.get_tree(&cur)?;
                tree.get(comp).cloned()
            }
            .ok_or_else(|| Error::Core(scl_core::Error::PathNotFound(path.to_string())))?;
            let last = i + 1 == comps.len();
            match (entry.kind, last) {
                (EntryKind::Tree, false) => cur = entry.id,
                (EntryKind::Tree, true) => {
                    return Err(Error::InvalidArgument(format!("{path} is a directory")))
                }
                (EntryKind::Blob, false) => {
                    return Err(Error::InvalidArgument(format!("{comp} is not a directory")))
                }
                (EntryKind::Blob, true) => {
                    if entry.perms & scl_core::PROTECTED != 0 {
                        return Err(Error::InvalidArgument(format!(
                            "{path} is a protected path; sc cat prints public content only"
                        )));
                    }
                    filler.ensure_present(&entry.id, path)?;
                    let store_arc = self.vfs.store();
                    let mut store = store_arc.lock().unwrap();
                    return match store.get(&entry.id)? {
                        Object::Blob(b) => Ok((b.to_vec(), filler.stats)),
                        _ => Err(Error::InvalidArgument(format!("{path} is not a file"))),
                    };
                }
            }
        }
        unreachable!("the loop returns on the last path component")
    }
}

/// Makes objects present, dialing the promisor remote only when the clone is
/// lazy and not offline. The connection opens on first need.
struct Filler<'a> {
    repo: &'a Repo,
    /// The promisor origin URL when filling is allowed, else `None`.
    origin: Option<String>,
    transport: Option<Box<dyn Transport>>,
    stats: FillStats,
}

impl<'a> Filler<'a> {
    fn new(repo: &'a Repo, offline: bool) -> Result<Filler<'a>> {
        let origin = match repo.promisor()? {
            Some(p) if crate::promisor::is_lazy(&repo.layout) && !offline => Some(p.origin),
            _ => None,
        };
        Ok(Filler {
            repo,
            origin,
            transport: None,
            stats: FillStats::default(),
        })
    }

    /// Ensure `id` is in the local store. `path` names what the caller is
    /// reading, for the gap error.
    fn ensure_present(&mut self, id: &ObjectId, path: &str) -> Result<()> {
        let present = self.repo.vfs.store().lock().unwrap().contains(id);
        if present {
            return Ok(());
        }
        let Some(origin) = self.origin.clone() else {
            return Err(if self.repo.promisor()?.is_some() {
                crate::promisor::partial_gap_hint(path)
            } else {
                Error::Core(scl_core::Error::NotFound(*id))
            });
        };
        if self.transport.is_none() {
            self.transport = Some(open_transport(&origin)?);
        }
        let transport = self.transport.as_deref().expect("opened above");
        let n = self.repo.fetch_by_id_from(transport, &[*id])?;
        self.stats.requests += 1;
        self.stats.objects += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// Source repo with `src/a.txt`, `docs/readme.md` and `docs/api/guide.md`.
    /// Returns the source root, its tip, and the ids of the `docs` tree,
    /// `docs/api` tree, `guide.md` blob and `readme.md` blob.
    struct Fixture {
        src_root: std::path::PathBuf,
        dst_root: std::path::PathBuf,
        tip: ObjectId,
        docs_tree: ObjectId,
        api_tree: ObjectId,
        guide_blob: ObjectId,
        readme_blob: ObjectId,
    }

    impl Fixture {
        fn new(tag: &str) -> Fixture {
            let pid = std::process::id();
            let src_root = std::env::temp_dir().join(format!("scl-fill-{tag}-src-{pid}"));
            let dst_root = std::env::temp_dir().join(format!("scl-fill-{tag}-dst-{pid}"));
            let _ = std::fs::remove_dir_all(&src_root);
            let _ = std::fs::remove_dir_all(&dst_root);
            std::fs::create_dir_all(src_root.join("src")).unwrap();
            std::fs::create_dir_all(src_root.join("docs/api")).unwrap();
            let src = Repo::init(&src_root).unwrap();
            std::fs::write(src_root.join("src/a.txt"), b"src-one").unwrap();
            std::fs::write(src_root.join("docs/readme.md"), b"readme body").unwrap();
            std::fs::write(src_root.join("docs/api/guide.md"), b"guide body").unwrap();
            let tip = src.commit("t", "c1").unwrap();
            let store_arc = src.vfs().store();
            let mut store = store_arc.lock().unwrap();
            let root = store.get_snapshot(&tip).unwrap().root;
            let docs_tree = store.get_tree(&root).unwrap().get("docs").unwrap().id;
            let docs = store.get_tree(&docs_tree).unwrap();
            let api_tree = docs.get("api").unwrap().id;
            let readme_blob = docs.get("readme.md").unwrap().id;
            let guide_blob = store
                .get_tree(&api_tree)
                .unwrap()
                .get("guide.md")
                .unwrap()
                .id;
            drop(store);
            drop(src);
            Fixture {
                src_root,
                dst_root,
                tip,
                docs_tree,
                api_tree,
                guide_blob,
                readme_blob,
            }
        }

        /// A partial clone filtered to `src/`.
        fn clone(&self, lazy: bool) -> Repo {
            let dst = Repo::clone_url_filtered(
                self.src_root.to_str().unwrap(),
                &self.dst_root,
                Some(&["src/".to_string()]),
            )
            .unwrap();
            crate::promisor::set_lazy(dst.layout(), lazy).unwrap();
            dst
        }

        fn has(&self, repo: &Repo, id: &ObjectId) -> bool {
            repo.vfs().store().lock().unwrap().contains(id)
        }

        fn cleanup(self) {
            for root in [&self.src_root, &self.dst_root] {
                if root.exists() {
                    std::fs::remove_dir_all(root).unwrap();
                }
                assert!(!root.exists(), "fixture {} must be removed", root.display());
            }
        }
    }

    #[test]
    fn cat_fills_only_the_path_it_reads() {
        let fx = Fixture::new("path");
        let dst = fx.clone(true);
        // The read path itself never touches the network: before any fill the
        // gapped objects are simply absent.
        assert!(dst
            .vfs()
            .store()
            .lock()
            .unwrap()
            .get_tree(&fx.docs_tree)
            .is_err());

        let (bytes, stats) = dst.cat_at_with_stats("main", "docs/api/guide.md").unwrap();
        assert_eq!(bytes, b"guide body");
        // docs tree, docs/api tree, guide blob: one round trip each, nothing else.
        assert_eq!(
            stats,
            FillStats {
                requests: 3,
                objects: 3
            }
        );
        assert!(fx.has(&dst, &fx.docs_tree));
        assert!(fx.has(&dst, &fx.api_tree));
        assert!(fx.has(&dst, &fx.guide_blob));
        assert!(
            !fx.has(&dst, &fx.readme_blob),
            "a sibling file must not be fetched"
        );

        // A second read of the same path is free.
        let (_, again) = dst.cat_at_with_stats("main", "docs/api/guide.md").unwrap();
        assert_eq!(again, FillStats::default());
        fx.cleanup();
    }

    #[test]
    fn cat_inside_the_filter_makes_no_request() {
        let fx = Fixture::new("infilter");
        let dst = fx.clone(true);
        let (bytes, stats) = dst.cat_at_with_stats("main", "src/a.txt").unwrap();
        assert_eq!(bytes, b"src-one");
        assert_eq!(stats, FillStats::default());
        fx.cleanup();
    }

    #[test]
    fn non_lazy_clone_keeps_the_gap_error() {
        let fx = Fixture::new("nonlazy");
        let dst = fx.clone(false);
        let err = dst.cat_at("main", "docs/readme.md").unwrap_err();
        assert!(matches!(err, Error::GapOutsideFilter(_)), "got {err:?}");
        assert!(!fx.has(&dst, &fx.docs_tree), "nothing may be fetched");
        fx.cleanup();
    }

    #[test]
    fn offline_forces_the_gap_error_even_when_lazy() {
        let fx = Fixture::new("offline");
        let dst = fx.clone(true);
        let err = dst.cat_at_impl("main", "docs/readme.md", true).unwrap_err();
        assert!(matches!(err, Error::GapOutsideFilter(_)), "got {err:?}");
        assert!(!fx.has(&dst, &fx.docs_tree));
        fx.cleanup();
    }

    #[test]
    fn a_retry_resumes_from_current_presence() {
        let fx = Fixture::new("resume");
        let dst = fx.clone(true);
        // Simulate a fill that died after the first level.
        let t = open_transport(fx.src_root.to_str().unwrap()).unwrap();
        dst.fetch_by_id_from(t.as_ref(), &[fx.docs_tree]).unwrap();
        assert!(fx.has(&dst, &fx.docs_tree));

        let (bytes, stats) = dst.cat_at_with_stats("main", "docs/api/guide.md").unwrap();
        assert_eq!(bytes, b"guide body");
        assert_eq!(
            stats,
            FillStats {
                requests: 2,
                objects: 2
            }
        );
        fx.cleanup();
    }

    #[test]
    fn gc_keeps_filled_objects_and_push_still_composes() {
        let fx = Fixture::new("gc");
        let dst = fx.clone(true);
        dst.cat_at("main", "docs/api/guide.md").unwrap();
        dst.gc(std::time::Duration::ZERO).unwrap();
        assert!(fx.has(&dst, &fx.guide_blob), "gc must keep filled objects");
        let (_, again) = dst.cat_at_with_stats("main", "docs/api/guide.md").unwrap();
        assert_eq!(again, FillStats::default());

        // A commit inside the filter after a fill pushes cleanly: the filter
        // is unchanged, so push sends in-filter objects only.
        std::fs::write(fx.dst_root.join("src/a.txt"), b"src-two").unwrap();
        dst.commit("t", "edit src").unwrap();
        dst.push("origin").unwrap();
        fx.cleanup();
    }

    #[test]
    fn cat_refuses_directories_missing_paths_and_unknown_refs() {
        let fx = Fixture::new("errors");
        let dst = fx.clone(true);
        assert!(matches!(
            dst.cat_at("main", "docs/api").unwrap_err(),
            Error::InvalidArgument(_)
        ));
        assert!(matches!(
            dst.cat_at("main", "docs/nope.md").unwrap_err(),
            Error::Core(scl_core::Error::PathNotFound(_))
        ));
        assert!(matches!(
            dst.cat_at("no-such-branch", "src/a.txt").unwrap_err(),
            Error::InvalidArgument(_)
        ));
        assert!(matches!(
            dst.cat_at("main", "/").unwrap_err(),
            Error::InvalidArgument(_)
        ));
        let _ = fx.tip;
        fx.cleanup();
    }

    #[test]
    fn verify_gap_count_is_unchanged_by_a_fill() {
        let fx = Fixture::new("verify");
        let dst = fx.clone(true);
        let before = dst.partial_gap_count(&[fx.tip]).unwrap();
        assert!(
            before.is_some_and(|n| n > 0),
            "docs/ is a gap before the fill"
        );
        dst.cat_at("main", "docs/api/guide.md").unwrap();
        assert_eq!(
            dst.partial_gap_count(&[fx.tip]).unwrap(),
            before,
            "a fill adds objects but never changes the filter, so the filter-scoped count is stable"
        );
        fx.cleanup();
    }

    #[test]
    fn cat_refuses_protected_paths_and_private_branches() {
        let root = std::env::temp_dir().join(format!("scl-fill-refuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("secret")).unwrap();
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"classified").unwrap();
        std::fs::write(root.join("open.txt"), b"public").unwrap();
        repo.commit("t", "base").unwrap();

        let err = repo.cat_at("main", "secret/a.txt").unwrap_err();
        assert!(
            matches!(&err, Error::InvalidArgument(m) if m.contains("protected")),
            "got {err:?}"
        );
        assert_eq!(repo.cat_at("main", "open.txt").unwrap(), b"public");

        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        let err = repo.cat_at("fix", "open.txt").unwrap_err();
        assert!(matches!(err, Error::PrivateUnsupported(_)), "got {err:?}");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// A transport that repeats one requested object many times, to prove the
    /// receiver stops at the requested record count instead of decompressing
    /// and hashing every duplicate.
    #[test]
    fn fetch_rejects_duplicate_records_before_processing_them_all() {
        let fx = Fixture::new("dups");
        let dst = fx.clone(true);
        let want = Object::blob(b"wanted".to_vec());
        let flood = Scripted {
            send: vec![want.clone(); 50],
            not_sent: vec![],
        };
        let err = dst.fetch_by_id_from(&flood, &[want.id()]).unwrap_err();
        assert!(
            matches!(&err, Error::Core(scl_core::Error::PackCorrupt(m)) if m.contains("requested")),
            "got {err:?}"
        );
        assert!(!fx.has(&dst, &want.id()), "a rejected pack lands nothing");
        fx.cleanup();
    }

    /// A transport whose `get_objects` replies with a scripted pack and
    /// not-sent list, to exercise the receiver's reply validation.
    struct Scripted {
        send: Vec<Object>,
        not_sent: Vec<ObjectId>,
    }

    impl Transport for Scripted {
        fn list_refs(&self) -> Result<Vec<(String, ObjectId)>> {
            unimplemented!()
        }
        fn head_branch(&self) -> Result<String> {
            unimplemented!()
        }
        fn has_object(&self, _: &ObjectId) -> Result<bool> {
            unimplemented!()
        }
        fn get_object(&self, _: &ObjectId) -> Result<Vec<u8>> {
            unimplemented!()
        }
        fn put_object(&self, _: &ObjectId, _: &[u8]) -> Result<()> {
            unimplemented!()
        }
        fn update_ref(&self, _: &str, _: &ObjectId, _: Option<&ObjectId>) -> Result<()> {
            unimplemented!()
        }
        fn get_pack(
            &self,
            _: &[ObjectId],
            _: &[ObjectId],
            _: Option<&[String]>,
            _: &mut dyn Write,
        ) -> Result<()> {
            unimplemented!()
        }
        fn put_pack(&self, _: &mut dyn Read) -> Result<Vec<ObjectId>> {
            unimplemented!()
        }
        fn get_objects(&self, _: &[ObjectId], out: &mut dyn Write) -> Result<Vec<ObjectId>> {
            let mut w = scl_core::pack::PackWriter::new(&mut *out, self.send.len() as u32)?;
            for o in &self.send {
                w.write_object(&o.id(), &o.encode())?;
            }
            w.finish()?;
            Ok(self.not_sent.clone())
        }
    }

    #[test]
    fn fetch_rejects_a_reply_that_does_not_partition_the_request() {
        let fx = Fixture::new("liar");
        let dst = fx.clone(true);
        let want = Object::blob(b"wanted".to_vec());
        let extra = Object::blob(b"smuggled".to_vec());
        let other = Object::blob(b"also requested".to_vec());
        let store_has = |id: &ObjectId| fx.has(&dst, id);

        // Unrequested object smuggled in, within the requested record count
        // (a longer pack is caught earlier by the record bound).
        let liar = Scripted {
            send: vec![want.clone(), extra.clone()],
            not_sent: vec![other.id()],
        };
        let err = dst
            .fetch_by_id_from(&liar, &[want.id(), other.id()])
            .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
        assert!(
            !store_has(&want.id()) && !store_has(&extra.id()),
            "nothing lands"
        );

        // Requested id neither sent nor refused.
        let liar = Scripted {
            send: vec![want.clone()],
            not_sent: vec![],
        };
        let err = dst
            .fetch_by_id_from(&liar, &[want.id(), other.id()])
            .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
        assert!(!store_has(&want.id()));

        // Sent and refused at once.
        let liar = Scripted {
            send: vec![want.clone()],
            not_sent: vec![want.id()],
        };
        assert!(matches!(
            dst.fetch_by_id_from(&liar, &[want.id()]).unwrap_err(),
            Error::Protocol(_)
        ));

        // A refused id is terminal, but what was sent is kept.
        let honest = Scripted {
            send: vec![want.clone()],
            not_sent: vec![other.id()],
        };
        let err = dst
            .fetch_by_id_from(&honest, &[want.id(), other.id()])
            .unwrap_err();
        assert!(matches!(err, Error::Core(scl_core::Error::NotFound(id)) if id == other.id()));
        assert!(store_has(&want.id()), "verified objects are retained");
        fx.cleanup();
    }
}
