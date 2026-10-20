//! Object/ref transport between repos. `LocalTransport` works over a remote
//! `.sc/` directory on the same filesystem; the trait is the seam for future
//! SSH/HTTP transports.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use scl_core::{Object, ObjectId, Store};

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::lock::RepoLock;

/// A remote repo we can list refs on and exchange content-addressed objects with.
pub trait Transport {
    /// `(branch, tip)` for every `refs/heads/*` on the remote.
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>>;
    /// The branch the remote HEAD names.
    fn head_branch(&self) -> Result<String>;
    /// True if the remote already holds an object with this id.
    fn has_object(&self, id: &ObjectId) -> Result<bool>;
    /// Raw canonical `encode()` bytes of an object.
    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>>;
    /// Write raw `encode()` bytes; verifies `ObjectId::of(bytes) == id`.
    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()>;
    /// Set `refs/heads/<branch>` on the remote to `id` — compare-and-swap.
    ///
    /// `expected_old` is the tip the caller based its fast-forward check on
    /// (`None` = the branch must not exist yet). The implementation must
    /// revalidate under the remote's own lock and refuse with
    /// [`Error::NonFastForward`] when the ref moved in between, so two racing
    /// pushers cannot silently clobber each other's commits. Setting the ref
    /// to the value it already has succeeds regardless of `expected_old`.
    fn update_ref(
        &self,
        branch: &str,
        id: &ObjectId,
        expected_old: Option<&ObjectId>,
    ) -> Result<()>;

    /// Stream a pack of every object reachable from `wants` but not already
    /// implied by `haves` (the receiver's closure) into `out`. An
    /// implementation may buffer internally before writing.
    ///
    /// `filter`, when `Some`, narrows the sender's `wants`-side walk to the
    /// given path prefixes (P27 Task 3) — the wire form of a partial clone's
    /// `.sc/promisor` prefix list, matched with the same `/`-boundary
    /// discipline as `Promisor::matches`/`should_descend`. The `haves`-side
    /// walk is always unfiltered (the receiver's full closure is excluded
    /// regardless of filter, since a filter only narrows what's sent, never
    /// widens what's assumed already held). `filter = None` reproduces the
    /// pre-P27 full-transfer behavior byte-for-byte.
    fn get_pack(
        &self,
        wants: &[ObjectId],
        haves: &[ObjectId],
        filter: Option<&[String]>,
        out: &mut dyn Write,
    ) -> Result<()>;

    /// Ingest a pack read from `src`: verify every record (BLAKE3) and write
    /// each object into the store. Returns the contained ids. Refs are the
    /// caller's job.
    fn put_pack(&self, src: &mut dyn Read) -> Result<Vec<ObjectId>>;

    /// Batched by-id fetch (P37, ADR-0047): write a pack holding every object
    /// of `ids` this remote can serve into `out`, and return the ids it did
    /// NOT send, in request order. "Not sent" covers both an id the remote
    /// lacks and an id it refuses to serve by id (sealed-branch objects), so
    /// the two cannot be told apart. At most
    /// [`crate::wire::MAX_GET_OBJECTS_IDS`] ids per call.
    ///
    /// The default refuses: only transports that can answer without a
    /// reachability walk (local path, wire clients) implement it.
    fn get_objects(&self, ids: &[ObjectId], out: &mut dyn Write) -> Result<Vec<ObjectId>> {
        let _ = (ids, out);
        Err(Error::InvalidArgument(
            "this remote does not support by-id object fetch".into(),
        ))
    }
}

/// The most canonical object bytes one by-id reply carries (ADR-0048). It sits
/// well under the client's 1 GiB read cap so pack record headers and zstd
/// framing cannot push a legitimate reply past it.
const BY_ID_REPLY_CAP: u64 = 512 << 20;

/// The by-id reply limit for a server whose `--max-pack-size` is
/// `max_pack_size` (0 means unlimited): the smaller of that and
/// [`BY_ID_REPLY_CAP`]. Shared by the wire server and [`LocalTransport`], so a
/// lazy clone of a local path cannot spool an unbounded reply either.
pub(crate) fn by_id_reply_cap(max_pack_size: u64) -> u64 {
    if max_pack_size == 0 {
        BY_ID_REPLY_CAP
    } else {
        max_pack_size.min(BY_ID_REPLY_CAP)
    }
}

/// Canonical encoded size of `obj`, computed without copying a large payload:
/// a blob or sealed object encodes as one tag byte plus its payload; the small
/// structural kinds are encoded to measure them.
fn encoded_len(obj: &Object) -> u64 {
    match obj {
        Object::Blob(b) => b.len() as u64 + 1,
        Object::Sealed(s) => s.payload.len() as u64 + 1,
        other => other.encode().len() as u64,
    }
}

/// Refuse an object a receiver would reject anyway: `pack::parse_pack_reader`
/// fails any record whose canonical encoding exceeds `MAX_OBJECT_SIZE`.
fn check_servable_size(id: &ObjectId, len: u64) -> Result<()> {
    if len > scl_core::MAX_OBJECT_SIZE as u64 {
        return Err(Error::PackTooLarge(format!(
            "object {id} exceeds MAX_OBJECT_SIZE and cannot be transferred"
        )));
    }
    Ok(())
}

/// Object kinds a by-id read never serves (ADR-0047): sealed private-branch
/// members and branch manifests. Filtered transfers already exclude them
/// (`filter_manifest_wants`); this keeps the by-id verb consistent with that
/// rule. It is a consistency rule, not a confidentiality boundary: sealed
/// objects are ciphertext and an unfiltered pack still serves them.
fn refused_by_id(obj: &Object) -> bool {
    matches!(obj, Object::Sealed(_) | Object::Manifest(_))
}

/// Transport over a remote `.sc/` directory on the local filesystem.
pub struct LocalTransport {
    layout: Layout,
    /// A store opened on the remote objects dir, so reads resolve loose
    /// (sharded or flat), compressed, and packed objects uniformly. Lazily
    /// mutated for its RAM cache; interior-mutable because the trait reads `&self`.
    store: RefCell<Store>,
}

impl LocalTransport {
    /// Open the repo whose root (the dir containing `.sc/`) is `root`.
    pub fn open(root: impl Into<std::path::PathBuf>) -> Result<LocalTransport> {
        let layout = Layout::at(root);
        if !layout.dot_sc.is_dir() {
            return Err(Error::NotARepo);
        }
        // Match the repo's store budget so a single large object never fails to resolve
        // (a blob bigger than the whole budget would BudgetExceed).
        let store = Store::open_persistent(layout.objects_dir(), crate::repo::DEFAULT_BUDGET)?;
        Ok(LocalTransport {
            layout,
            store: RefCell::new(store),
        })
    }

    /// Resolve a by-id request against this store into a temp pack of the
    /// servable objects, returning `(not_sent, pack)` (P37, ADR-0047). The
    /// shared core of [`Transport::get_objects`] and `wire::serve`'s
    /// `GetObjects` arm. Duplicate ids are served once. `max_bytes` (0 =
    /// unlimited) bounds the summed canonical encoded size, and any single
    /// object over `MAX_OBJECT_SIZE` is refused (every receiver would reject
    /// it). Both fail with `PackTooLarge` before any pack byte is written.
    /// Blobs and sealed objects are measured without re-encoding them.
    pub(crate) fn build_objects_tempfile(
        &self,
        ids: &[ObjectId],
        max_bytes: u64,
    ) -> Result<(Vec<ObjectId>, TempPackGuard)> {
        use std::collections::BTreeSet;
        let mut store = self.store.borrow_mut();
        let mut seen = BTreeSet::new();
        let mut found = Vec::new();
        let mut not_sent = Vec::new();
        let mut total: u64 = 0;
        for id in ids {
            if !seen.insert(*id) {
                continue;
            }
            match store.get(id) {
                Ok(obj) if refused_by_id(&obj) => not_sent.push(*id),
                Ok(obj) => {
                    let size = encoded_len(&obj);
                    check_servable_size(id, size)?;
                    total = total.saturating_add(size);
                    if max_bytes > 0 && total > max_bytes {
                        return Err(Error::PackTooLarge(format!(
                            "by-id response exceeds the {max_bytes}-byte limit"
                        )));
                    }
                    found.push(*id);
                }
                Err(scl_core::Error::NotFound(_)) => not_sent.push(*id),
                Err(e) => return Err(e.into()),
            }
        }
        let guard = write_ids_to_temp_pack(&self.layout, &mut store, &found)?;
        Ok((not_sent, guard))
    }

    /// This transport's layout — `wire::serve` (a sibling module) needs it to
    /// spill an incoming chunk stream to a temp pack file before handing the
    /// path to [`ingest_pack_file`] directly (P25), bypassing a second
    /// `Transport::put_pack`-level spill.
    pub(crate) fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Bounded pack sender (P25): gather the transfer set exactly as before,
    /// but instead of collecting every object's encoded bytes into one
    /// `Vec<(ObjectId, Vec<u8>)>` (unbounded RAM) and calling `build_pack`,
    /// stream each object straight into a fresh temp pack file via
    /// `PackWriter` — peak RAM is one object's encoded + compressed bytes.
    /// Returns an RAII-guarded path to the finished pack file; the caller
    /// reads it and the guard removes it on drop (success or error alike).
    /// Shared by `Transport::get_pack` (one bounded copy into `out`) and
    /// `wire::serve`'s `GetPack` handling (one `write_pack_stream` straight
    /// off this same file — no second spill).
    ///
    /// `filter` (P27 Task 3), when `Some`, narrows only the `wants`-side walk
    /// via `reachable_objects_filtered` — the `.included` set becomes the
    /// pack's object set instead of the unfiltered `reachable_objects`
    /// result. The `haves`-side walk is always the full unfiltered
    /// reachability of each have tip: haves describe what the receiver
    /// already holds, and a filter never widens that assumption, so
    /// excluding "everything the client has" must stay exact regardless of
    /// whether the sender is also narrowing what it sends.
    pub(crate) fn build_pack_tempfile(
        &self,
        wants: &[ObjectId],
        haves: &[ObjectId],
        filter: Option<&[String]>,
    ) -> Result<TempPackGuard> {
        use std::collections::BTreeSet;
        let mut store = self.store.borrow_mut();
        // Reachable-from-wants minus reachable-from-haves, computed on this
        // (the remote) store. `haves` the remote doesn't have are skipped.
        let promisor_filter =
            filter.map(|prefixes| crate::promisor::Promisor::new(String::new(), prefixes.to_vec()));
        // Filtered transfers exclude private branches entirely (ADR-0044):
        // a want that resolves to a branch manifest is dropped before the
        // walk. Serves both transports — the wire server's GetPack delegates
        // here.
        let wants =
            crate::reachable::filter_manifest_wants(&mut *store, wants, promisor_filter.is_some())?;
        let mut want_set = match &promisor_filter {
            Some(pf) => {
                crate::reachable::reachable_objects_filtered(
                    &mut *store,
                    &wants,
                    Some(pf as &dyn crate::reachable::PrefixFilter),
                )?
                .included
            }
            None => crate::reachable::reachable_objects(&mut *store, &wants)?,
        };

        let mut have_set: BTreeSet<ObjectId> = BTreeSet::new();
        for h in haves {
            if store.contains(h) {
                have_set.extend(crate::reachable::reachable_objects(&mut *store, &[*h])?);
            }
        }

        // Sender seam (P22 Task 3, carried through the P25 bounded rewrite
        // unchanged): a SignatureObj is a leaf referenced by no tree/
        // snapshot, so the reachability walks above never find it on their
        // own — it has to be pulled in explicitly via the `.sc/signatures`
        // index. See the (now-moved) original comment history in the P22/P25
        // diffs for the retroactive-signing rationale; behavior is
        // unchanged: over-send every indexed signature covering any
        // transfer-relevant snapshot, never subtract any of them from
        // `have_set`.
        let all_snaps: Vec<ObjectId> = want_set.iter().chain(have_set.iter()).copied().collect();
        // Sender seam (P30 Task 4, mirroring the signature over-send
        // verbatim): a Transcript is likewise a leaf referenced by no
        // tree/snapshot, so it has to be pulled in explicitly via the
        // `.sc/transcripts` index. Compute these BEFORE the signature
        // over-send below — a transcript's own signature lives in the
        // SHARED `.sc/signatures` index keyed by the transcript's own id
        // (not the snapshot's), so `indexed_signature_ids_for` must be
        // queried over snapshots AND transcript ids together, or a signed
        // transcript's signature never crosses the wire (review-caught: an
        // earlier draft queried signatures over `all_snaps` alone, so a
        // `sc transcript attach --sign` survived clone/fetch/push as an
        // object but landed `Unsigned` on the far side).
        let transcript_ids =
            crate::transcripts::indexed_transcript_ids_for(&self.layout, &all_snaps)?;
        let sig_targets: Vec<ObjectId> = all_snaps
            .iter()
            .chain(transcript_ids.iter())
            .copied()
            .collect();
        want_set.extend(crate::signatures::indexed_signature_ids_for(
            &self.layout,
            &sig_targets,
        )?);
        // Over-send every indexed transcript covering any transfer-relevant
        // snapshot; never subtract any of them from `have_set` — the
        // has-gated filter below still applies.
        want_set.extend(transcript_ids);

        let ids: Vec<ObjectId> = want_set
            .into_iter()
            .filter(|id| !have_set.contains(id))
            .collect();

        write_ids_to_temp_pack(&self.layout, &mut store, &ids)
    }

    /// Bounded pack receiver (P25): ingest an already-on-disk pack file
    /// (produced either by `Transport::put_pack`'s own spill, below, or by
    /// `wire::serve` destreaming an incoming chunk stream) via
    /// [`ingest_pack_file`]'s two-pass atomic-after-verify contract.
    pub(crate) fn ingest_from(&self, path: &std::path::Path) -> Result<Vec<ObjectId>> {
        let mut store = self.store.borrow_mut();
        ingest_pack_file(&self.layout, &mut store, path)
    }
}

/// RAII guard for a per-transfer temporary pack file under `.sc/tmp/`
/// (P25). Removes the file on drop — success, verification failure, or a
/// dropped connection alike — so a streamed pack transfer never leaves
/// residue outside `.sc/`. Reserves a path unique enough for concurrent
/// transfers within one process (pid + a monotonic per-process counter);
/// does not remove `.sc/tmp/` itself, matching how other `.sc/` subdirs
/// (e.g. `.sc/ws/`) are left in place between uses.
pub(crate) struct TempPackGuard {
    path: std::path::PathBuf,
}

impl TempPackGuard {
    /// Create `.sc/tmp/` if needed and reserve a fresh path inside it. The
    /// file itself is not created here — callers open/create it themselves
    /// (as a writer for a fresh spill, or a reader once written).
    pub(crate) fn new(layout: &Layout) -> Result<TempPackGuard> {
        Self::new_in(&layout.tmp_dir())
    }

    /// Like [`TempPackGuard::new`], but reserves the path directly under an
    /// arbitrary directory rather than deriving it from a repo `Layout` — the
    /// seam a bucket-backed serve session (P36c) uses, since a bucket remote
    /// has no `.sc/tmp/` of its own to spool into and spills instead into an
    /// RAII scratch dir for the session's lifetime.
    pub(crate) fn new_in(dir: &std::path::Path) -> Result<TempPackGuard> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        std::fs::create_dir_all(dir)?;
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("pack-{}-{n}.tmp", std::process::id()));
        Ok(TempPackGuard { path })
    }

    /// The reserved path.
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempPackGuard {
    fn drop(&mut self) {
        // Best-effort: a file that was never created (an error before the
        // first write) is a no-op `remove_file` failure, not a bug.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Write the objects named by `ids` (already fully resolved — no reachability
/// or have-set filtering here, that's the caller's job) into a fresh guarded
/// temp pack file via `PackWriter`, one object at a time. Peak RAM is one
/// object's encoded + compressed bytes. Shared by
/// [`LocalTransport::build_pack_tempfile`] (the remote-side sender, which
/// resolves `ids` via reachability) and `Repo::push` (P25's client-side
/// sender, which resolves `ids` via a local reachability walk filtered by
/// `Transport::has_object`) — one ids-to-temp-pack-file implementation, not
/// two.
pub(crate) fn write_ids_to_temp_pack(
    layout: &Layout,
    store: &mut Store,
    ids: &[ObjectId],
) -> Result<TempPackGuard> {
    let guard = TempPackGuard::new(layout)?;
    {
        let mut f = std::fs::File::create(guard.path())?;
        let mut writer = scl_core::pack::PackWriter::new(&mut f, ids.len() as u32)?;
        for id in ids {
            let bytes = store.get(id)?.encode();
            writer.write_object(id, &bytes)?;
        }
        writer.finish()?; // .idx discarded — transfer needs the .pack body only
    }
    Ok(guard)
}

/// Ingest a pack **file** into `store`, atomically after verification
/// (P25's correctness heart): pass 1 walks every record via
/// `parse_pack_reader`, verifying its BLAKE3 hash, and writes nothing; pass 2
/// walks the same file again, this time writing each verified object into
/// `store`. A corrupt record anywhere in the pack is therefore caught in
/// pass 1, before any object from THIS pack reaches the store — a
/// corrupt/tampered transfer never partially lands. Peak RAM is one record's
/// compressed + decompressed bytes, whichever pass is running — the file on
/// disk, not a `Vec<u8>`, is the thing being re-read.
///
/// # Why re-reading the file (not the untrusted wire) is what makes the
/// per-record length prefix safe (Task 1 carry-in #1)
///
/// Two defenses now compose here (updated for P28 Task 2). First,
/// `parse_pack_reader` itself hard-rejects any record whose compressed
/// length prefix, or whose decompressed zstd output, exceeds
/// `MAX_OBJECT_SIZE` (256 MiB) — an absolute per-record cap enforced
/// regardless of source. Second, and independently, both passes here read
/// the *already-fully-spilled* temp file rather than the live connection
/// (whether it was spilled by `Transport::put_pack`'s own bounded copy from
/// `src`, or by `wire::serve` destreaming a chunked wire transfer): the
/// total bytes any record's length prefix can possibly claim is also
/// bounded by the file's own size on disk, which was itself bounded by
/// however many bytes the sender actually sent. So a hostile length prefix
/// is now rejected outright by the `MAX_OBJECT_SIZE` cap, and even absent
/// that cap could never claim more than the attacker already transferred —
/// both defenses hold. Every call site in this codebase (both here and
/// `wire::serve`'s own dispatch) reads a spilled file, never the live
/// connection.
///
/// # Task 1 carry-in #2 (exact-EOF framing)
///
/// `parse_pack_reader` also relies on its source ending EXACTLY at the last
/// record. `Transport::put_pack`'s spill uses `std::io::copy(src, &mut f)`
/// (writes exactly what `src` produced, nothing appended); `wire::serve`'s
/// spill uses `read_pack_stream`, which writes exactly the streamed pack
/// body and returns once `ST_PACK_END` is seen (nothing trails it either).
/// Both temp files therefore end exactly at the last record, matching
/// `parse_pack_reader`'s termination contract.
pub(crate) fn ingest_pack_file(
    layout: &Layout,
    store: &mut Store,
    path: &std::path::Path,
) -> Result<Vec<ObjectId>> {
    ingest_pack_file_checked(layout, store, path, None, |_| Ok(()))
}

/// [`ingest_pack_file`] with a gate between its two passes (P37): `check`
/// sees the set of ids pass 1 verified and may veto the whole pack, so a
/// receiver that knows what it asked for (`Repo`'s by-id fill) can reject
/// unrequested objects before any of them is written. `max_records` aborts
/// pass 1 as soon as the pack holds more records than the caller asked for,
/// so a peer cannot make the receiver decompress and hash the same large
/// object over and over (a set of ids hides duplicate records).
pub(crate) fn ingest_pack_file_checked(
    layout: &Layout,
    store: &mut Store,
    path: &std::path::Path,
    max_records: Option<usize>,
    check: impl FnOnce(&std::collections::BTreeSet<ObjectId>) -> Result<()>,
) -> Result<Vec<ObjectId>> {
    ingest_pack_file_impl(layout, store, path, max_records, check, false)
}

/// [`ingest_pack_file`] for a `--no-transcripts` receiver (ADR-0038 addendum,
/// #211): every record is still hash-checked in pass 1 (not
/// signature-verified), but pass 2 does not
/// write `Transcript` objects, nor a signature whose target is a transcript
/// dropped from this same pack (it would index against a transcript that is
/// not here). The sender over-sends regardless of what the receiver wants (no
/// wire flag), so this saves disk and exposure, not bandwidth.
pub(crate) fn ingest_pack_file_without_transcripts(
    layout: &Layout,
    store: &mut Store,
    path: &std::path::Path,
) -> Result<Vec<ObjectId>> {
    ingest_pack_file_impl(layout, store, path, None, |_| Ok(()), true)
}

fn ingest_pack_file_impl(
    layout: &Layout,
    store: &mut Store,
    path: &std::path::Path,
    max_records: Option<usize>,
    check: impl FnOnce(&std::collections::BTreeSet<ObjectId>) -> Result<()>,
    skip_transcripts: bool,
) -> Result<Vec<ObjectId>> {
    // Transcript ids seen in pass 1; pass 2 uses them to also drop their signatures.
    let mut dropped = std::collections::BTreeSet::new();
    // Pass 1: verify every record's hash; write nothing.
    {
        let f = std::fs::File::open(path)?;
        let mut seen = std::collections::BTreeSet::new();
        let mut records = 0usize;
        scl_core::pack::parse_pack_reader(f, |id, obj| {
            records += 1;
            if max_records.is_some_and(|max| records > max) {
                return Err(scl_core::Error::PackCorrupt(format!(
                    "pack holds more than the {} record(s) requested",
                    max_records.unwrap_or(0)
                )));
            }
            if skip_transcripts && matches!(obj, scl_core::Object::Transcript(_)) {
                dropped.insert(id);
            }
            seen.insert(id);
            Ok(())
        })?;
        check(&seen)?;
    }
    // Pass 2: every record verified in pass 1 — now write each into the store.
    let f = std::fs::File::open(path)?;
    let mut ids = Vec::new();
    scl_core::pack::parse_pack_reader(f, |id, obj| {
        if dropped.contains(&id)
            || matches!(&obj, scl_core::Object::Signature(s) if dropped.contains(&s.snapshot))
        {
            return Ok(());
        }
        let got = store.put(obj)?;
        // Defense in depth: pass 1 already verified this record's hash; this
        // guards against a future change that weakens that.
        if got != id {
            return Err(scl_core::Error::PackCorrupt(format!(
                "packed object {id} landed under a different id ({got})"
            )));
        }
        ids.push(id);
        Ok(())
    })?;
    // Receiver seam (P22 Task 3): every id above was just written to this
    // store, so `index_incoming`'s "ids just written" contract holds.
    crate::signatures::index_incoming(layout, store, &ids)?;
    // Receiver seam (P30 Task 4): same "ids just written" contract, for
    // Transcript objects.
    crate::transcripts::index_incoming(layout, store, &ids)?;
    Ok(ids)
}

impl Transport for LocalTransport {
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>> {
        let mut out = Vec::new();
        let dir = self.layout.refs_heads_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for e in entries {
            let e = e?;
            if e.file_type()?.is_file() {
                let name = e.file_name().to_string_lossy().into_owned();
                let text = std::fs::read_to_string(e.path())?;
                let id = ObjectId::from_str(text.trim())
                    .map_err(|_| Error::BadRef(format!("remote ref {name} has bad id")))?;
                out.push((name, id));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    fn head_branch(&self) -> Result<String> {
        crate::refs::current_branch(&self.layout)
    }

    fn has_object(&self, id: &ObjectId) -> Result<bool> {
        Ok(self.store.borrow().contains(id))
    }

    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>> {
        Ok(self.store.borrow_mut().get(id)?.encode())
    }

    fn get_objects(&self, ids: &[ObjectId], out: &mut dyn Write) -> Result<Vec<ObjectId>> {
        if ids.len() > crate::wire::MAX_GET_OBJECTS_IDS {
            return Err(Error::InvalidArgument(format!(
                "by-id fetch takes at most {} ids per call",
                crate::wire::MAX_GET_OBJECTS_IDS
            )));
        }
        let (not_sent, guard) = self.build_objects_tempfile(ids, by_id_reply_cap(0))?;
        let mut f = std::fs::File::open(guard.path())?;
        std::io::copy(&mut f, out)?;
        Ok(not_sent)
    }

    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        if ObjectId::of(bytes) != *id {
            return Err(Error::CorruptObject(*id));
        }
        let got = self.store.borrow_mut().put(Object::decode(bytes)?)?;
        if got != *id {
            return Err(Error::CorruptObject(*id));
        }
        Ok(())
    }

    fn update_ref(
        &self,
        branch: &str,
        id: &ObjectId,
        expected_old: Option<&ObjectId>,
    ) -> Result<()> {
        let _lock = RepoLock::acquire(&self.layout)?;
        // Revalidate inside the lock: the caller's fast-forward check ran
        // unlocked, so the ref may have moved since (two concurrent pushes).
        let current = crate::refs::read_branch_tip(&self.layout, branch)?;
        if current.as_ref() == Some(id) {
            return Ok(()); // already there — idempotent, nothing moves
        }
        // A stopped merge, cherry-pick or rebase here is completed against the
        // checked-out branch's tip: moving that tip from underneath it would
        // make the completing commit silently drop what was pushed (the P19-I1
        // discard shape, reached by a remote writer). Refuse before any
        // write; other branches are unaffected. HEAD is read only when an op
        // is stopped, and a failure to read it then fails closed: the op's
        // state exists, so a push must not guess which branch it belongs to.
        let stopped = if crate::merge_state::in_progress(&self.layout) {
            Some(Error::MergeInProgress)
        } else if crate::pick_state::in_progress(&self.layout) {
            Some(Error::PickInProgress)
        } else if crate::rebase_state::in_progress(&self.layout) {
            Some(Error::RebaseInProgress)
        } else {
            None
        };
        if let Some(err) = stopped {
            if crate::refs::current_branch(&self.layout)? == branch {
                return Err(err);
            }
        }
        if current.as_ref() != expected_old {
            return Err(Error::NonFastForward);
        }
        crate::refs::write_branch_tip(&self.layout, branch, id)
    }

    /// Bounded sender (P25): builds the transfer set into a temp pack file
    /// via `LocalTransport::build_pack_tempfile` (peak RAM one object),
    /// then copies that file's raw bytes into `out` with a small fixed
    /// buffer (`std::io::copy`) — `out` still receives exactly the raw
    /// `.pack` bytes `build_pack` used to hand back directly, so every
    /// existing caller of this trait method (`sync::transfer_objects`, the
    /// `fetch_transfers_only_delta_not_full_history` regression test) is
    /// unaffected. `wire::serve`'s `GetPack` handling does NOT go through
    /// this method — it calls `build_pack_tempfile` itself and streams the
    /// same temp file straight onto the wire in `ST_PACK_CHUNK` frames, so
    /// there is exactly one spill either way, never two.
    fn get_pack(
        &self,
        wants: &[ObjectId],
        haves: &[ObjectId],
        filter: Option<&[String]>,
        out: &mut dyn Write,
    ) -> Result<()> {
        let guard = self.build_pack_tempfile(wants, haves, filter)?;
        let mut f = std::fs::File::open(guard.path())?;
        std::io::copy(&mut f, out)?;
        Ok(())
    }

    /// Bounded receiver (P25): spills `src` to a temp pack file with a small
    /// fixed buffer (`std::io::copy` — bounded RAM, and writes exactly what
    /// `src` produced, satisfying Task 1 carry-in #2's exact-EOF framing
    /// requirement), then ingests it via `ingest_pack_file`'s two-pass
    /// atomic-after-verify contract (see that function's doc comment for the
    /// full correctness argument, including Task 1 carry-in #1). The temp
    /// file is removed on drop regardless of outcome.
    ///
    /// # Caller contract on `Err`
    ///
    /// Treat any `Err` return as "the pack was not fully applied" — with the
    /// P25 two-pass rewrite this is now backed by a real guarantee: a
    /// corrupt/tampered pack is rejected in pass 1 before any object of it
    /// reaches the store. Do **not** update refs on failure. The only
    /// remaining non-atomicity is a `store.put` failure mid-pass-2 (e.g.
    /// disk full) on an already-verified pack; any objects written before
    /// that point are durably stored and harmless (content-addressed,
    /// reclaimable by `sc gc`). Retrying is always safe (idempotent `put`).
    fn put_pack(&self, src: &mut dyn Read) -> Result<Vec<ObjectId>> {
        let guard = TempPackGuard::new(&self.layout)?;
        {
            let mut f = std::fs::File::create(guard.path())?;
            std::io::copy(src, &mut f)?;
        }
        self.ingest_from(guard.path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::Object;

    fn tmp_remote(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-xport-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(layout.objects_dir()).unwrap();
        std::fs::create_dir_all(layout.refs_heads_dir()).unwrap();
        crate::refs::write_head(&layout, "main").unwrap();
        layout
    }

    #[test]
    fn local_get_objects_serves_found_and_reports_the_rest_not_sent() {
        let layout = tmp_remote("getobjs");
        let t = LocalTransport::open(&layout.root).unwrap();
        let blob = Object::blob(b"servable".to_vec());
        let sealed = Object::Sealed(scl_core::SealedObj {
            payload: std::sync::Arc::from(b"ciphertext".to_vec().into_boxed_slice()),
        });
        let manifest = Object::Manifest(scl_core::BranchManifest {
            base: blob.id(),
            prev: None,
            anchors: vec![],
            closure: vec![sealed.id()],
            index_ct: vec![1, 2, 3],
            kek_wraps: vec![],
        });
        let absent = Object::blob(b"never stored".to_vec());
        for o in [&blob, &sealed, &manifest] {
            t.put_object(&o.id(), &o.encode()).unwrap();
        }

        let mut out = Vec::new();
        let not_sent = t
            .get_objects(
                &[
                    blob.id(),
                    sealed.id(),
                    manifest.id(),
                    absent.id(),
                    blob.id(),
                ],
                &mut out,
            )
            .unwrap();
        // Sealed and Manifest are refused and absent is missing; the three
        // are not distinguishable, and a duplicate request id is served once.
        assert_eq!(not_sent, vec![sealed.id(), manifest.id(), absent.id()]);
        let got = scl_core::pack::parse_pack(&out).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, blob.id());

        // All-missing still yields a valid (empty) pack.
        let mut out = Vec::new();
        let not_sent = t.get_objects(&[absent.id()], &mut out).unwrap();
        assert_eq!(not_sent, vec![absent.id()]);
        assert!(scl_core::pack::parse_pack(&out).unwrap().is_empty());

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn encoded_len_matches_the_canonical_encoding_and_the_receiver_limit() {
        let blob = Object::blob(vec![1u8; 300]);
        let sealed = Object::Sealed(scl_core::SealedObj {
            payload: std::sync::Arc::from(vec![2u8; 300].into_boxed_slice()),
        });
        let tree = Object::Tree(scl_core::Tree {
            entries: vec![scl_core::TreeEntry {
                name: "a.txt".into(),
                kind: scl_core::EntryKind::Blob,
                id: blob.id(),
                mode: scl_core::FileMode(0o644),
                perms: 0,
            }],
        });
        for o in [&blob, &sealed, &tree] {
            assert_eq!(encoded_len(o), o.encode().len() as u64, "{}", o.kind_name());
        }
        let id = blob.id();
        // The receiver rejects a canonical encoding above MAX_OBJECT_SIZE, and
        // the encoding of a blob is its payload plus one tag byte.
        let max = scl_core::MAX_OBJECT_SIZE as u64;
        assert!(check_servable_size(&id, max).is_ok());
        assert!(matches!(
            check_servable_size(&id, max + 1),
            Err(Error::PackTooLarge(_))
        ));
        assert_eq!(encoded_len(&Object::blob(vec![0u8; 10])), 11);
    }

    #[test]
    fn small_structural_objects_count_against_the_reply_cap() {
        let layout = tmp_remote("getobjs-tree-cap");
        let t = LocalTransport::open(&layout.root).unwrap();
        let blob = Object::blob(b"x".to_vec());
        let entries: Vec<scl_core::TreeEntry> = (0..20)
            .map(|i| scl_core::TreeEntry {
                name: format!("file-{i:02}.txt"),
                kind: scl_core::EntryKind::Blob,
                id: blob.id(),
                mode: scl_core::FileMode(0o644),
                perms: 0,
            })
            .collect();
        let tree = Object::Tree(scl_core::Tree { entries });
        t.put_object(&tree.id(), &tree.encode()).unwrap();
        // A tree carries no blob payload but is several hundred bytes encoded;
        // a 50-byte cap must refuse it.
        assert!(matches!(
            t.build_objects_tempfile(&[tree.id()], 50),
            Err(Error::PackTooLarge(_))
        ));
        assert!(t.build_objects_tempfile(&[tree.id()], 0).is_ok());
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn local_get_objects_enforces_the_size_cap_and_id_cap() {
        let layout = tmp_remote("getobjs-cap");
        let t = LocalTransport::open(&layout.root).unwrap();
        let blob = Object::blob(vec![7u8; 4096]);
        t.put_object(&blob.id(), &blob.encode()).unwrap();
        assert!(matches!(
            t.build_objects_tempfile(&[blob.id()], 100),
            Err(Error::PackTooLarge(_))
        ));
        let too_many = vec![blob.id(); crate::wire::MAX_GET_OBJECTS_IDS + 1];
        assert!(matches!(
            t.get_objects(&too_many, &mut Vec::new()),
            Err(Error::InvalidArgument(_))
        ));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn local_transport_objects_and_refs_roundtrip() {
        let layout = tmp_remote("rt");
        let t = LocalTransport::open(&layout.root).unwrap();

        let blob = Object::blob(b"hello".to_vec());
        let id = blob.id();
        let bytes = blob.encode();
        assert!(!t.has_object(&id).unwrap());
        t.put_object(&id, &bytes).unwrap();
        assert!(t.has_object(&id).unwrap());
        assert_eq!(t.get_object(&id).unwrap(), bytes);

        // corrupt put is rejected
        assert!(matches!(
            t.put_object(&id, b"not the bytes"),
            Err(Error::CorruptObject(_))
        ));

        t.update_ref("main", &id, None).unwrap();
        assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), id)]);
        assert_eq!(t.head_branch().unwrap(), "main");

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn update_ref_is_compare_and_swap() {
        // Two pushers can both pass the fast-forward check against the same old
        // tip; the ref write itself must revalidate under the remote lock so
        // the second writer fails instead of silently clobbering the first.
        let layout = tmp_remote("cas");
        let t = LocalTransport::open(&layout.root).unwrap();
        let c1 = Object::blob(b"c1".to_vec()).id();
        let c2 = Object::blob(b"c2".to_vec()).id();
        let c3 = Object::blob(b"c3".to_vec()).id();

        // Create: expected None means "branch must not exist".
        t.update_ref("main", &c1, None).unwrap();
        // Creating again with expected None must fail (it exists now).
        assert!(matches!(
            t.update_ref("main", &c2, None),
            Err(Error::NonFastForward)
        ));

        // Advance with the right expected old tip.
        t.update_ref("main", &c2, Some(&c1)).unwrap();

        // A raced writer still expecting c1 must fail, not clobber c2.
        assert!(matches!(
            t.update_ref("main", &c3, Some(&c1)),
            Err(Error::NonFastForward)
        ));
        assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), c2)]);

        // Re-pushing the value already at the tip is fine (idempotent), even
        // with a stale expectation — the ref ends up exactly where asked.
        t.update_ref("main", &c2, Some(&c1)).unwrap();
        t.update_ref("main", &c2, Some(&c2)).unwrap();

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn wire_update_ref_rejects_traversal() {
        // LocalTransport::update_ref is the choke point the wire UpdateRef
        // arm (wire.rs) reaches on the server side, so driving it directly
        // here exercises the same code path a hostile ssh/http client's
        // UpdateRef request would hit.
        let layout = tmp_remote("wire-update-ref");
        let t = LocalTransport::open(&layout.root).unwrap();
        let id = Object::blob(b"hello".to_vec()).id();

        assert!(matches!(
            t.update_ref("../../escape", &id, None),
            Err(Error::BadRef(_))
        ));
        assert!(matches!(
            t.update_ref("has space", &id, None),
            Err(Error::BadRef(_))
        ));

        // No ref file was created anywhere, including outside refs/heads/.
        assert_eq!(t.list_refs().unwrap(), Vec::new());
        assert!(!layout.root.join("escape").exists());
        assert!(!layout.root.parent().unwrap().join("escape").exists());

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn transport_reads_object_larger_than_one_mib() {
        // A blob > 1 MiB would BudgetExceed under the old 1 MiB budget.
        let layout = tmp_remote("large");
        let big_bytes: Vec<u8> = vec![0xAB; (1 << 20) + 4096];
        let blob = Object::blob(big_bytes);
        let id = blob.id();
        let expected = blob.encode();
        {
            let mut s =
                scl_core::Store::open_persistent(layout.objects_dir(), crate::repo::DEFAULT_BUDGET)
                    .unwrap();
            s.put(Object::blob(vec![0xAB; (1 << 20) + 4096])).unwrap();
        }
        let t = LocalTransport::open(&layout.root).unwrap();
        let got = t
            .get_object(&id)
            .expect("large object must transfer without BudgetExceeded");
        assert_eq!(got, expected);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn transport_reads_packed_remote_object() {
        let layout = tmp_remote("packed");
        // Write an object into the remote store, pack it, drop the loose copy.
        let id;
        {
            let mut s = scl_core::Store::open_persistent(layout.objects_dir(), 1 << 20).unwrap();
            id = s.put(Object::blob(b"remote-packed".to_vec())).unwrap();
            let _h = s.write_pack(&[id]).unwrap();
            s.delete(&id).unwrap();
        }
        let t = LocalTransport::open(&layout.root).unwrap();
        assert!(t.has_object(&id).unwrap());
        assert_eq!(
            t.get_object(&id).unwrap(),
            Object::blob(b"remote-packed".to_vec()).encode()
        );
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn get_pack_excludes_haves_and_put_pack_verifies() {
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-xport-bulk-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-xport-bulkdst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        std::fs::create_dir_all(&src_root).unwrap();
        std::fs::create_dir_all(&dst_root).unwrap();

        // Seed two reachable commits on the remote via a real repo.
        let remote_repo = crate::repo::Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("a.txt"), b"one").unwrap();
        let c1 = remote_repo.commit("t", "c1").unwrap();
        std::fs::write(src_root.join("a.txt"), b"two").unwrap();
        let c2 = remote_repo.commit("t", "c2").unwrap();

        let t = LocalTransport::open(&src_root).unwrap();
        // Want c2, already have c1: the pack must omit c1's objects but include c2.
        let mut pack = Vec::new();
        t.get_pack(&[c2], &[c1], None, &mut pack).unwrap();
        let ids: Vec<_> = scl_core::pack::parse_pack(&pack)
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert!(ids.contains(&c2));
        assert!(!ids.contains(&c1));

        // put_pack into a fresh empty remote writes + returns the ids.
        let _ = crate::repo::Repo::init(&dst_root).unwrap();
        let t2 = LocalTransport::open(&dst_root).unwrap();
        let written = t2.put_pack(&mut &pack[..]).unwrap();
        assert!(written.contains(&c2));
        assert!(t2.has_object(&c2).unwrap());

        // A tampered pack is rejected.
        let mut bad = pack.clone();
        let n = bad.len() - 1;
        bad[n] ^= 0xFF;
        assert!(t2.put_pack(&mut &bad[..]).is_err());

        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    /// P27 Task 3: a `get_pack` with `filter = Some(["src/"])` must send only
    /// the in-filter subtree — the `docs/b` blob must never reach the
    /// receiving store, while the root tree and snapshot (structure, not
    /// content) always transfer so the receiver's tree stays well-formed.
    #[test]
    fn filtered_get_pack_excludes_out_of_prefix() {
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-xport-filt-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-xport-filtdst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        std::fs::create_dir_all(&src_root).unwrap();
        std::fs::create_dir_all(&dst_root).unwrap();

        let remote_repo = crate::repo::Repo::init(&src_root).unwrap();
        std::fs::create_dir_all(src_root.join("src")).unwrap();
        std::fs::create_dir_all(src_root.join("docs")).unwrap();
        std::fs::write(src_root.join("src/a"), b"src-a").unwrap();
        std::fs::write(src_root.join("docs/b"), b"docs-b").unwrap();
        let tip = remote_repo.commit("t", "c1").unwrap();
        let src_a_id = Object::blob(b"src-a".to_vec()).id();
        let docs_b_id = Object::blob(b"docs-b".to_vec()).id();

        let t = LocalTransport::open(&src_root).unwrap();
        let root_id = match Object::decode(&t.get_object(&tip).unwrap()).unwrap() {
            Object::Snapshot(s) => s.root,
            other => panic!("expected snapshot, got {other:?}"),
        };
        let mut pack = Vec::new();
        t.get_pack(&[tip], &[], Some(&["src/".to_string()]), &mut pack)
            .unwrap();

        let _ = crate::repo::Repo::init(&dst_root).unwrap();
        let t2 = LocalTransport::open(&dst_root).unwrap();
        t2.put_pack(&mut &pack[..]).unwrap();

        assert!(t2.has_object(&tip).unwrap(), "snapshot must transfer");
        assert!(t2.has_object(&root_id).unwrap(), "root tree must transfer");
        assert!(
            t2.has_object(&src_a_id).unwrap(),
            "in-filter blob must transfer"
        );
        assert!(
            !t2.has_object(&docs_b_id).unwrap(),
            "out-of-filter blob must NOT transfer"
        );

        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    /// `filter = None` must still transfer everything reachable — the P27
    /// filter parameter must not disturb the pre-P27 full-transfer path.
    #[test]
    fn full_get_pack_unchanged() {
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-xport-full-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-xport-fulldst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        std::fs::create_dir_all(&src_root).unwrap();
        std::fs::create_dir_all(&dst_root).unwrap();

        let remote_repo = crate::repo::Repo::init(&src_root).unwrap();
        std::fs::create_dir_all(src_root.join("src")).unwrap();
        std::fs::create_dir_all(src_root.join("docs")).unwrap();
        std::fs::write(src_root.join("src/a"), b"src-a").unwrap();
        std::fs::write(src_root.join("docs/b"), b"docs-b").unwrap();
        let tip = remote_repo.commit("t", "c1").unwrap();
        let src_a_id = Object::blob(b"src-a".to_vec()).id();
        let docs_b_id = Object::blob(b"docs-b".to_vec()).id();

        let t = LocalTransport::open(&src_root).unwrap();
        let mut pack = Vec::new();
        t.get_pack(&[tip], &[], None, &mut pack).unwrap();

        let _ = crate::repo::Repo::init(&dst_root).unwrap();
        let t2 = LocalTransport::open(&dst_root).unwrap();
        t2.put_pack(&mut &pack[..]).unwrap();

        assert!(t2.has_object(&tip).unwrap());
        assert!(t2.has_object(&src_a_id).unwrap());
        assert!(
            t2.has_object(&docs_b_id).unwrap(),
            "unfiltered transfer must still include everything"
        );

        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    fn tmp_dir_is_empty(layout: &Layout) -> bool {
        match std::fs::read_dir(layout.tmp_dir()) {
            Ok(mut entries) => entries.next().is_none(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => panic!("unexpected error reading .sc/tmp: {e}"),
        }
    }

    /// P25 correctness heart, exercised directly against `LocalTransport`
    /// (the sibling `stdio_transport::streaming_receiver_leaves_zero_residue_on_success_and_error`
    /// exercises the same guarantee through the actual chunked wire path —
    /// this test pins the underlying `ingest_pack_file`/`TempPackGuard`
    /// contract in isolation, with no wire framing in the way).
    #[test]
    fn put_pack_leaves_zero_residue_on_success_and_error() {
        let layout = tmp_remote("residue");
        let t = LocalTransport::open(&layout.root).unwrap();

        let a = Object::blob(b"alpha".to_vec());
        let b = Object::blob(b"bravo bravo".to_vec());
        let (pack, _idx) =
            scl_core::pack::build_pack(&[(a.id(), a.encode()), (b.id(), b.encode())]).unwrap();

        // Success: both objects land, and the temp pack file is gone.
        let written = t.put_pack(&mut &pack[..]).unwrap();
        assert_eq!(written.len(), 2);
        assert!(t.has_object(&a.id()).unwrap());
        assert!(t.has_object(&b.id()).unwrap());
        assert!(
            tmp_dir_is_empty(&layout),
            "temp pack file must be gone after a successful put_pack"
        );

        // Failure: corrupt the one record's compressed payload. Pass 1 of
        // ingest_pack_file must reject it BEFORE any write, so the object
        // must not land, and the temp file must still be cleaned up.
        let c = Object::blob(b"charlie charlie charlie".to_vec());
        let (mut pack2, _idx2) = scl_core::pack::build_pack(&[(c.id(), c.encode())]).unwrap();
        let last = pack2.len() - 1;
        pack2[last] ^= 0xFF;

        assert!(t.put_pack(&mut &pack2[..]).is_err());
        assert!(
            !t.has_object(&c.id()).unwrap(),
            "corrupt pack must not land any object — atomic after verify"
        );
        assert!(
            tmp_dir_is_empty(&layout),
            "temp pack file must be gone after a corrupt ingest too"
        );

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn by_id_reply_cap_is_the_smaller_of_max_pack_size_and_512_mib() {
        const MIB: u64 = 1 << 20;
        // 0 means "unlimited" for --max-pack-size, but a by-id reply is still
        // bounded so the client's read cap always covers it.
        assert_eq!(by_id_reply_cap(0), 512 * MIB);
        assert_eq!(by_id_reply_cap(64 * MIB), 64 * MIB);
        assert_eq!(by_id_reply_cap(16 << 30), 512 * MIB);
    }

    /// A repo with a stopped merge, pick or rebase is completed against its
    /// checked-out branch's tip. A push moving that tip would make the
    /// completing commit drop the pushed work, so it is refused (other
    /// branches are untouched), and allowed again once the op is over.
    #[test]
    fn update_ref_refuses_the_checked_out_branch_during_a_stopped_op() {
        let root = std::env::temp_dir().join(format!("scl-xport-stopped-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("t", "base").unwrap();
        repo.branch("other").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nMAIN\nc\n").unwrap();
        let main_tip = repo.commit("t", "main").unwrap();
        repo.switch("other").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nOTHER\nc\n").unwrap();
        repo.commit("t", "other").unwrap();
        repo.switch("main").unwrap();
        assert!(repo.merge("other", "t").is_err(), "setup: a stopped merge");
        assert!(repo.merge_in_progress());
        // The pushed-to repo's own process has exited (a Repo handle holds the
        // single-writer lock the transport needs).
        let layout = repo.layout().clone();
        drop(repo);

        let t = LocalTransport::open(&root).unwrap();
        let pushed = Object::blob(b"pushed".to_vec()).id();
        // The checked-out branch: refused, and nothing moved.
        assert!(matches!(
            t.update_ref("main", &pushed, Some(&main_tip)),
            Err(Error::MergeInProgress)
        ));
        assert_eq!(
            crate::refs::read_branch_tip(&layout, "main").unwrap(),
            Some(main_tip)
        );
        // A retry of a push that already landed moves nothing: still accepted.
        t.update_ref("main", &main_tip, None).unwrap();
        // An unreadable HEAD with a stopped op fails closed, not open.
        let head_path = layout.head_path();
        let head_text = std::fs::read(&head_path).unwrap();
        std::fs::remove_file(&head_path).unwrap();
        assert!(
            t.update_ref("main", &pushed, Some(&main_tip)).is_err(),
            "a push must not guess the checked-out branch while an op is stopped"
        );
        assert_eq!(
            crate::refs::read_branch_tip(&layout, "main").unwrap(),
            Some(main_tip)
        );
        std::fs::write(&head_path, head_text).unwrap();
        // A branch that is not checked out is not in the way.
        t.update_ref("elsewhere", &pushed, None).unwrap();
        assert_eq!(
            crate::refs::read_branch_tip(&layout, "elsewhere").unwrap(),
            Some(pushed)
        );
        // Once the merge is over the push lands.
        drop(t);
        let repo = crate::repo::Repo::open(&root).unwrap();
        repo.merge_abort().unwrap();
        drop(repo);
        let t = LocalTransport::open(&root).unwrap();
        t.update_ref("main", &pushed, Some(&main_tip)).unwrap();
        drop(t);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// The same receiving-side refusal for a stopped cherry-pick.
    #[test]
    fn update_ref_refuses_the_checked_out_branch_during_a_stopped_pick() {
        let root = std::env::temp_dir().join(format!("scl-xport-pick-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("t", "base").unwrap();
        repo.branch("other").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nMAIN\nc\n").unwrap();
        let main_tip = repo.commit("t", "main").unwrap();
        repo.switch("other").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nOTHER\nc\n").unwrap();
        repo.commit("t", "other").unwrap();
        repo.switch("main").unwrap();
        assert!(repo.cherry_pick("other", "t", None, None).is_err());
        assert!(repo.pick_in_progress());
        drop(repo);

        let t = LocalTransport::open(&root).unwrap();
        let pushed = Object::blob(b"pushed".to_vec()).id();
        assert!(matches!(
            t.update_ref("main", &pushed, Some(&main_tip)),
            Err(Error::PickInProgress)
        ));
        drop(t);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }
}
