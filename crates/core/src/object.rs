//! Object model and canonical serialization.
//!
//! Every object is serialized to a deterministic byte form whose BLAKE3 hash is
//! its [`ObjectId`]. The encoding is length-prefixed and tree entries are sorted,
//! so the same logical content always produces the same address on any machine.

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::id::ObjectId;

/// Object kind tags, written as the first byte of every encoding.
pub(crate) const TAG_BLOB: u8 = 0;
const TAG_TREE: u8 = 1;
const TAG_SNAPSHOT_LEGACY: u8 = 2; // pre-P16 encoding; refused with a clear error
const TAG_SECRET: u8 = 3;
const TAG_SNAPSHOT: u8 = 4;
const TAG_SIGNATURE: u8 = 5;
const TAG_TRANSCRIPT: u8 = 6;
const TAG_SEALED: u8 = 7;
const TAG_MANIFEST: u8 = 8;

/// Perms-byte bit: this blob entry holds a `nonce‖ciphertext` envelope (an
/// encrypted file), not plaintext. Set on protected-path entries (P7).
pub const PROTECTED: u8 = 0b0000_0001;

/// Perms flag: this PROTECTED entry was sealed with a fresh random DEK+nonce
/// (P33) rather than convergently. Always set together with `PROTECTED`.
/// Format identification for dual-read lives here, in the tree entry, so no
/// caller ever needs to fetch blob bytes to know the seal format.
pub const RANDOMIZED: u8 = 0b0000_0010;

/// A recipient's standing on a protected prefix: active or tombstoned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecipientState {
    Granted,
    Revoked,
}

/// One recipient's standing on a protected prefix — a last-writer-wins
/// register ordered by `epoch`. A `Revoked` entry IS the tombstone that keeps
/// a revocation durable across merges (ADR-0026): rule merges keep the
/// higher-epoch entry, so a pre-revoke branch cannot resurrect the grant.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecipientEntry {
    pub key: [u8; 32],
    pub epoch: u32,
    pub state: RecipientState,
}

/// A protected path prefix and the per-recipient standing registers used at
/// commit time to decide who new files' DEKs are wrapped for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProtectPrefix {
    pub prefix: String,
    pub recipients: Vec<RecipientEntry>,
}

impl ProtectPrefix {
    /// The effective recipient set: keys with `Granted` standing. This is the
    /// only set sealing may wrap DEKs for — tombstoned keys are excluded.
    pub fn granted_keys(&self) -> Vec<[u8; 32]> {
        self.recipients
            .iter()
            .filter(|e| e.state == RecipientState::Granted)
            .map(|e| e.key)
            .collect()
    }

    /// The epoch a new standing change on this prefix must carry to win over
    /// every existing entry.
    pub fn next_epoch(&self) -> u32 {
        self.recipients.iter().map(|e| e.epoch).max().unwrap_or(0) + 1
    }

    /// Set `key`'s register to (`epoch`, `state`), inserting it if absent.
    pub fn set_standing(&mut self, key: [u8; 32], epoch: u32, state: RecipientState) {
        match self.recipients.iter_mut().find(|e| e.key == key) {
            Some(e) => {
                e.epoch = epoch;
                e.state = state;
            }
            None => self.recipients.push(RecipientEntry { key, epoch, state }),
        }
    }
}

/// Per-snapshot encrypted-path policy: which prefixes are protected (+ for whom),
/// and the per-recipient wrapped DEKs keyed by the ciphertext blob's id.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Protection {
    pub prefixes: Vec<ProtectPrefix>,
    pub wrapped: std::collections::BTreeMap<ObjectId, Vec<WrappedKey>>,
}

/// Whether a tree entry points at file content or a subtree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryKind {
    Blob,
    Tree,
}

/// Unix-style file mode (permission + type bits). `0o644` is a normal file,
/// `0o755` an executable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileMode(pub u32);

impl FileMode {
    pub const FILE: FileMode = FileMode(0o644);
    pub const EXEC: FileMode = FileMode(0o755);
}

/// One entry in a directory listing.
///
/// `perms` is a reserved per-file permission bitset — unused by the MVP but
/// carried in the on-disk format so the long-term per-file permission model
/// lands without a format change.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TreeEntry {
    pub name: String,
    pub kind: EntryKind,
    pub id: ObjectId,
    pub mode: FileMode,
    pub perms: u8,
}

/// A directory: a list of entries kept sorted by name for canonical encoding.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
}

impl Tree {
    pub fn new(mut entries: Vec<TreeEntry>) -> Self {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Tree { entries }
    }

    pub fn get(&self, name: &str) -> Option<&TreeEntry> {
        self.entries
            .binary_search_by(|e| e.name.as_str().cmp(name))
            .ok()
            .map(|i| &self.entries[i])
    }
}

/// The Jujutsu-inspired analogue of a commit: a root tree plus metadata.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Snapshot {
    pub root: ObjectId,
    pub parents: Vec<ObjectId>,
    pub author: String,
    pub timestamp: i64,
    pub message: String,
    /// Side registry of committed secrets, `name -> Secret object id`. Separate
    /// from the file tree: secrets are env vars, not files, and are never
    /// materialized by `checkout`. A `BTreeMap` iterates in sorted key order, so
    /// the canonical encoding (and thus `id()`) is independent of insertion order.
    pub secrets: std::collections::BTreeMap<String, ObjectId>,
    /// Encrypted-path policy (P7): protected prefixes + per-ciphertext wrapped
    /// DEKs. Canonical encoding (sorted prefixes + ordered map) keeps the id
    /// order-independent.
    pub protection: Protection,
}

/// A DEK wrapped (encrypted) for one authorized recipient public key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WrappedKey {
    pub recipient_id: String,
    pub wrapped_dek: Vec<u8>,
}

/// An envelope-encrypted secret (Phase 2). Stored and addressed exactly like any
/// other object, so it flows through fork/checkout/clone untouched and stays
/// ciphertext until an authorized context unwraps a DEK.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Secret {
    pub name: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub wrapped_keys: Vec<WrappedKey>,
}

/// A detached Ed25519 signature over a snapshot id (P22 provenance). `core`
/// stays crypto-free: this struct is raw bytes only — nothing here knows how
/// to produce or verify a signature. `crates/crypto` owns
/// `sign_snapshot_id`/`verify_snapshot_sig`; `crates/repo` composes them with
/// this object and its CAS storage. Content-addressed like any other object,
/// so signing the same snapshot with the same key twice (Ed25519 signing is
/// deterministic) always yields the same object id — a natural idempotency
/// key for `sign_snapshot`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignatureObj {
    /// The snapshot this signature covers.
    pub snapshot: ObjectId,
    /// The signer's raw 32-byte Ed25519 verifying-key bytes.
    pub signer: [u8; 32],
    /// The raw 64-byte Ed25519 signature.
    pub sig: [u8; 64],
}

/// A sealed agent-session transcript (P30): the session that motivated
/// `snapshot`, encrypted like a `Secret` (fresh random DEK, wrapped per
/// recipient) so plaintext never enters the CAS. `agent`/`session` are
/// opaque metadata labels; the body is opaque bytes (no schema).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    pub snapshot: ObjectId,
    pub agent: String,
    pub session: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub wrapped_keys: Vec<WrappedKey>,
}

/// A sealed private-branch object (P34, ADR-0044): the canonical encoding of
/// some inner object (snapshot, tree, or blob) encrypted under a fresh random
/// per-object DEK — payload is `nonce(24) ‖ AEAD ciphertext`. Which inner kind
/// it holds, and the DEK that opens it, live only in the branch manifest's
/// encrypted index; to everyone else this is opaque bytes with a random-looking
/// content address. A distinct tag (not `Blob`) so ciphertext can never be
/// misread as plaintext file content.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedObj {
    pub payload: Arc<[u8]>,
}

/// A private branch's manifest (P34, ADR-0044) — the object a private branch's
/// ref points at instead of a snapshot. Plaintext *structure*, sealed content:
/// keyless parties (gc, transports) get exactly what they need — the closure
/// list and the public base — and nothing else.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BranchManifest {
    /// The public fork-point snapshot. Kept plaintext so gc can keep the base
    /// (and its closure) alive even if the public branch later rewrites it
    /// away — publish and merge-base walks need it present. This is a
    /// deliberate, documented metadata leak (the fork point is visible).
    pub base: ObjectId,
    /// The manifest this one supersedes (`None` at branch creation). Manifests
    /// form the private branch's meta-history the way parents do for
    /// snapshots: the fast-forward check on push walks this chain, and gc
    /// keeps superseded manifests (and their closures) reachable exactly as
    /// it keeps ancestor snapshots.
    pub prev: Option<ObjectId>,
    /// Public snapshot roots the sealed trees reference but that are NOT
    /// reachable from `base` — the tips merged in from public branches by
    /// `merge_into_private` (P34). A merged-in public object is carried into
    /// the sealed inner tree as an unsealed public reference (copy-on-write,
    /// never re-sealed — it's already public), so without an explicit
    /// reachability anchor a keyless party walking the manifest could never
    /// reach it (it can't walk the sealed tree), and pushing just the private
    /// branch to a peer lacking those public commits would strand the tree.
    /// Cumulative across the branch's history and sorted (canonical). Leaks
    /// which public commits were merged in — the same class of metadata as
    /// `base` already leaking the fork point.
    pub anchors: Vec<ObjectId>,
    /// Every sealed object id in the branch's closure, sorted (canonical).
    /// gc: manifest reachable ⇒ all listed ids reachable. Transport: diff this
    /// flat list against the peer's haves. Leaks count + sizes by design.
    pub closure: Vec<ObjectId>,
    /// The branch index — `inner id -> (sealed id, DEK)` plus the inner tip —
    /// encrypted under the branch KEK (`nonce ‖ AEAD`). Opaque to `core`;
    /// `crates/crypto` owns the index codec and the KEK envelope.
    pub index_ct: Vec<u8>,
    /// The branch KEK wrapped per recipient (and escrow), P2-shape envelope.
    pub kek_wraps: Vec<WrappedKey>,
}

/// Any object the store can hold. Blob bytes are `Arc`-shared so forking many
/// worktrees off one snapshot never copies file content.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Object {
    Blob(Arc<[u8]>),
    Tree(Tree),
    Snapshot(Snapshot),
    Secret(Secret),
    Signature(SignatureObj),
    Transcript(Transcript),
    Sealed(SealedObj),
    Manifest(BranchManifest),
}

impl Object {
    pub fn blob(bytes: impl Into<Vec<u8>>) -> Object {
        Object::Blob(Arc::from(bytes.into().into_boxed_slice()))
    }

    /// Bytes counted against the store's blob budget (0 for small resident
    /// kinds). Sealed payloads are blob-sized ciphertext and get the same
    /// budget/eviction treatment as plaintext blobs.
    pub fn blob_size(&self) -> usize {
        match self {
            Object::Blob(b) => b.len(),
            Object::Sealed(s) => s.payload.len(),
            _ => 0,
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Object::Blob(_) => "blob",
            Object::Tree(_) => "tree",
            Object::Snapshot(_) => "snapshot",
            Object::Secret(_) => "secret",
            Object::Signature(_) => "signature",
            Object::Transcript(_) => "transcript",
            Object::Sealed(_) => "sealed",
            Object::Manifest(_) => "manifest",
        }
    }

    /// The content address of this object.
    pub fn id(&self) -> ObjectId {
        ObjectId::of(&self.encode())
    }

    // ---- canonical encoding -------------------------------------------------

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Object::Blob(b) => {
                w.tag(TAG_BLOB);
                w.raw(b);
            }
            Object::Tree(t) => {
                w.tag(TAG_TREE);
                w.u32(t.entries.len() as u32);
                for e in &t.entries {
                    w.str(&e.name);
                    w.u8(match e.kind {
                        EntryKind::Blob => 0,
                        EntryKind::Tree => 1,
                    });
                    w.id(&e.id);
                    w.u32(e.mode.0);
                    w.u8(e.perms);
                }
            }
            Object::Snapshot(s) => {
                w.tag(TAG_SNAPSHOT);
                w.id(&s.root);
                w.u32(s.parents.len() as u32);
                for p in &s.parents {
                    w.id(p);
                }
                w.str(&s.author);
                w.i64(s.timestamp);
                w.str(&s.message);
                w.u32(s.secrets.len() as u32);
                for (name, id) in &s.secrets {
                    w.str(name);
                    w.id(id);
                }
                // protection: prefixes (sorted by prefix) then wrapped map.
                let mut prefixes = s.protection.prefixes.clone();
                prefixes.sort_by(|a, b| a.prefix.cmp(&b.prefix));
                w.u32(prefixes.len() as u32);
                for p in &prefixes {
                    w.str(&p.prefix);
                    w.u32(p.recipients.len() as u32);
                    // Sort registers by key so the same logical policy hashes
                    // identically regardless of insertion order.
                    let mut sorted = p.recipients.clone();
                    sorted.sort_unstable_by_key(|a| a.key);
                    for r in &sorted {
                        w.raw(&r.key); // 32 bytes
                        w.u32(r.epoch);
                        w.u8(match r.state {
                            RecipientState::Granted => 0,
                            RecipientState::Revoked => 1,
                        });
                    }
                }
                w.u32(s.protection.wrapped.len() as u32);
                for (id, wks) in &s.protection.wrapped {
                    w.id(id);
                    w.u32(wks.len() as u32);
                    for k in wks {
                        w.str(&k.recipient_id);
                        w.bytes(&k.wrapped_dek);
                    }
                }
            }
            Object::Secret(s) => {
                w.tag(TAG_SECRET);
                w.str(&s.name);
                w.bytes(&s.nonce);
                w.bytes(&s.ciphertext);
                w.u32(s.wrapped_keys.len() as u32);
                for k in &s.wrapped_keys {
                    w.str(&k.recipient_id);
                    w.bytes(&k.wrapped_dek);
                }
            }
            Object::Signature(s) => {
                w.tag(TAG_SIGNATURE);
                w.id(&s.snapshot);
                w.raw(&s.signer); // fixed 32 bytes — no length prefix needed
                w.raw(&s.sig); // fixed 64 bytes — no length prefix needed
            }
            Object::Transcript(t) => {
                w.tag(TAG_TRANSCRIPT);
                w.id(&t.snapshot);
                w.str(&t.agent);
                w.str(&t.session);
                w.bytes(&t.nonce);
                w.bytes(&t.ciphertext);
                w.u32(t.wrapped_keys.len() as u32);
                for wk in &t.wrapped_keys {
                    w.str(&wk.recipient_id);
                    w.bytes(&wk.wrapped_dek);
                }
            }
            Object::Sealed(s) => {
                w.tag(TAG_SEALED);
                w.raw(&s.payload);
            }
            Object::Manifest(m) => {
                w.tag(TAG_MANIFEST);
                w.id(&m.base);
                match &m.prev {
                    Some(p) => {
                        w.u8(1);
                        w.id(p);
                    }
                    None => w.u8(0),
                }
                // Sort anchors then closure so the same logical set hashes
                // identically regardless of insertion order.
                let mut anchors = m.anchors.clone();
                anchors.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                w.u32(anchors.len() as u32);
                for id in &anchors {
                    w.id(id);
                }
                let mut closure = m.closure.clone();
                closure.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                w.u32(closure.len() as u32);
                for id in &closure {
                    w.id(id);
                }
                w.bytes(&m.index_ct);
                w.u32(m.kek_wraps.len() as u32);
                for k in &m.kek_wraps {
                    w.str(&k.recipient_id);
                    w.bytes(&k.wrapped_dek);
                }
            }
        }
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Result<Object> {
        let mut r = Reader::new(bytes);
        let tag = r.u8()?;
        let obj = match tag {
            TAG_BLOB => Object::Blob(Arc::from(r.rest())),
            TAG_TREE => {
                let n = r.count()?;
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    let name = r.str()?;
                    let kind = match r.u8()? {
                        0 => EntryKind::Blob,
                        1 => EntryKind::Tree,
                        k => return Err(Error::Malformed(format!("bad entry kind {k}"))),
                    };
                    let id = r.id()?;
                    let mode = FileMode(r.u32()?);
                    let perms = r.u8()?;
                    entries.push(TreeEntry {
                        name,
                        kind,
                        id,
                        mode,
                        perms,
                    });
                }
                Object::Tree(Tree { entries })
            }
            TAG_SNAPSHOT_LEGACY => {
                return Err(Error::Malformed(
                    "pre-P16 snapshot encoding (tag 2): this store predates the ADR-0026 \
                     protection-rule format break and cannot be read by this version"
                        .into(),
                ))
            }
            TAG_SNAPSHOT => {
                let root = r.id()?;
                let np = r.count()?;
                let mut parents = Vec::with_capacity(np);
                for _ in 0..np {
                    parents.push(r.id()?);
                }
                let author = r.str()?;
                let timestamp = r.i64()?;
                let message = r.str()?;
                let ns = r.count()?;
                let mut secrets = std::collections::BTreeMap::new();
                for _ in 0..ns {
                    let name = r.str()?;
                    let id = r.id()?;
                    secrets.insert(name, id);
                }
                let n_prefixes = r.count()?;
                let mut prefixes = Vec::with_capacity(n_prefixes);
                for _ in 0..n_prefixes {
                    let prefix = r.str()?;
                    let n_recipients = r.count()?;
                    let mut recipients = Vec::with_capacity(n_recipients);
                    for _ in 0..n_recipients {
                        let mut rk = [0u8; 32];
                        rk.copy_from_slice(r.take(32)?);
                        let epoch = r.u32()?;
                        let state = match r.u8()? {
                            0 => RecipientState::Granted,
                            1 => RecipientState::Revoked,
                            s => return Err(Error::Malformed(format!("bad recipient state {s}"))),
                        };
                        recipients.push(RecipientEntry {
                            key: rk,
                            epoch,
                            state,
                        });
                    }
                    prefixes.push(ProtectPrefix { prefix, recipients });
                }
                let n_wrapped = r.count()?;
                let mut wrapped = std::collections::BTreeMap::new();
                for _ in 0..n_wrapped {
                    let id = r.id()?;
                    let n_keys = r.count()?;
                    let mut wks = Vec::with_capacity(n_keys);
                    for _ in 0..n_keys {
                        let recipient_id = r.str()?;
                        let wrapped_dek = r.bytes()?;
                        wks.push(WrappedKey {
                            recipient_id,
                            wrapped_dek,
                        });
                    }
                    wrapped.insert(id, wks);
                }
                let protection = Protection { prefixes, wrapped };
                Object::Snapshot(Snapshot {
                    root,
                    parents,
                    author,
                    timestamp,
                    message,
                    secrets,
                    protection,
                })
            }
            TAG_SECRET => {
                let name = r.str()?;
                let nonce = r.bytes()?;
                let ciphertext = r.bytes()?;
                let nk = r.count()?;
                let mut wrapped_keys = Vec::with_capacity(nk);
                for _ in 0..nk {
                    let recipient_id = r.str()?;
                    let wrapped_dek = r.bytes()?;
                    wrapped_keys.push(WrappedKey {
                        recipient_id,
                        wrapped_dek,
                    });
                }
                Object::Secret(Secret {
                    name,
                    nonce,
                    ciphertext,
                    wrapped_keys,
                })
            }
            TAG_SIGNATURE => {
                let snapshot = r.id()?;
                let mut signer = [0u8; 32];
                signer.copy_from_slice(r.take(32)?);
                let mut sig = [0u8; 64];
                sig.copy_from_slice(r.take(64)?);
                // Strict decode: fixed-width fields only, no trailing bytes.
                if r.remaining() != 0 {
                    return Err(Error::Malformed(
                        "trailing bytes in signature object".into(),
                    ));
                }
                Object::Signature(SignatureObj {
                    snapshot,
                    signer,
                    sig,
                })
            }
            TAG_TRANSCRIPT => {
                let snapshot = r.id()?;
                let agent = r.str()?;
                let session = r.str()?;
                let nonce = r.bytes()?;
                let ciphertext = r.bytes()?;
                let nk = r.count()?;
                let mut wrapped_keys = Vec::with_capacity(nk);
                for _ in 0..nk {
                    let recipient_id = r.str()?;
                    let wrapped_dek = r.bytes()?;
                    wrapped_keys.push(WrappedKey {
                        recipient_id,
                        wrapped_dek,
                    });
                }
                Object::Transcript(Transcript {
                    snapshot,
                    agent,
                    session,
                    nonce,
                    ciphertext,
                    wrapped_keys,
                })
            }
            TAG_SEALED => Object::Sealed(SealedObj {
                payload: Arc::from(r.rest()),
            }),
            TAG_MANIFEST => {
                let base = r.id()?;
                let prev = match r.u8()? {
                    0 => None,
                    1 => Some(r.id()?),
                    b => return Err(Error::Malformed(format!("bad manifest prev marker {b}"))),
                };
                let na = r.count()?;
                let mut anchors = Vec::with_capacity(na);
                for _ in 0..na {
                    anchors.push(r.id()?);
                }
                let nc = r.count()?;
                let mut closure = Vec::with_capacity(nc);
                for _ in 0..nc {
                    closure.push(r.id()?);
                }
                let index_ct = r.bytes()?;
                let nk = r.count()?;
                let mut kek_wraps = Vec::with_capacity(nk);
                for _ in 0..nk {
                    let recipient_id = r.str()?;
                    let wrapped_dek = r.bytes()?;
                    kek_wraps.push(WrappedKey {
                        recipient_id,
                        wrapped_dek,
                    });
                }
                Object::Manifest(BranchManifest {
                    base,
                    prev,
                    anchors,
                    closure,
                    index_ct,
                    kek_wraps,
                })
            }
            t => return Err(Error::Malformed(format!("unknown object tag {t}"))),
        };
        Ok(obj)
    }
}

// ---- tiny length-prefixed codec --------------------------------------------

#[derive(Default)]
struct Writer(Vec<u8>);

impl Writer {
    fn tag(&mut self, t: u8) {
        self.0.push(t);
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn id(&mut self, id: &ObjectId) {
        self.0.extend_from_slice(id.as_bytes());
    }
    fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(Error::Malformed("unexpected end of object".into()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// Bytes not yet consumed.
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    /// Read a `u32` element count and reject it if it exceeds the bytes left in
    /// the reader. Every element consumes at least one byte, so a count larger
    /// than the remaining bytes is fabricated — rejecting it before allocating
    /// prevents a multi-GB `Vec::with_capacity` from a malicious snapshot.
    fn count(&mut self) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > self.remaining() {
            return Err(Error::Malformed(
                "element count exceeds remaining bytes".into(),
            ));
        }
        Ok(n)
    }
    fn i64(&mut self) -> Result<i64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(i64::from_be_bytes(a))
    }
    fn id(&mut self) -> Result<ObjectId> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(ObjectId::from_bytes(a))
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn str(&mut self) -> Result<String> {
        let b = self.bytes()?;
        String::from_utf8(b).map_err(|e| Error::Malformed(e.to_string()))
    }
    fn rest(&mut self) -> Vec<u8> {
        let s = self.buf[self.pos..].to_vec();
        self.pos = self.buf.len();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_roundtrip_and_dedup() {
        let a = Object::blob(b"hello".to_vec());
        let b = Object::blob(b"hello".to_vec());
        assert_eq!(a.id(), b.id(), "identical content must share an address");
        let decoded = Object::decode(&a.encode()).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]
    fn tree_is_canonical_regardless_of_input_order() {
        let id = Object::blob(b"x".to_vec()).id();
        let e = |n: &str| TreeEntry {
            name: n.into(),
            kind: EntryKind::Blob,
            id,
            mode: FileMode::FILE,
            perms: 0,
        };
        let t1 = Tree::new(vec![e("b"), e("a"), e("c")]);
        let t2 = Tree::new(vec![e("c"), e("b"), e("a")]);
        assert_eq!(Object::Tree(t1).id(), Object::Tree(t2).id());
    }

    #[test]
    fn snapshot_and_secret_roundtrip() {
        let snap = Object::Snapshot(Snapshot {
            root: Object::blob(b"r".to_vec()).id(),
            parents: vec![],
            author: "agent".into(),
            timestamp: 42,
            message: "init".into(),
            secrets: std::collections::BTreeMap::new(),
            protection: Protection::default(),
        });
        assert_eq!(snap, Object::decode(&snap.encode()).unwrap());

        let sec = Object::Secret(Secret {
            name: "API_KEY".into(),
            nonce: vec![1, 2, 3],
            ciphertext: vec![9, 9, 9, 9],
            wrapped_keys: vec![WrappedKey {
                recipient_id: "key-1".into(),
                wrapped_dek: vec![7; 32],
            }],
        });
        assert_eq!(sec, Object::decode(&sec.encode()).unwrap());
    }

    #[test]
    fn snapshot_with_secrets_roundtrips_and_is_order_independent() {
        let sid = Object::Secret(Secret {
            name: "API_KEY".into(),
            nonce: vec![1, 2, 3],
            ciphertext: vec![9; 8],
            wrapped_keys: vec![],
        })
        .id();
        let root = Object::blob(b"r".to_vec()).id();
        let base = |secrets: std::collections::BTreeMap<String, ObjectId>| {
            Object::Snapshot(Snapshot {
                root,
                parents: vec![],
                author: "a".into(),
                timestamp: 0,
                message: "m".into(),
                secrets,
                protection: Protection::default(),
            })
        };
        // Two registries built from differently-ordered inputs.
        let mut m1 = std::collections::BTreeMap::new();
        m1.insert("DB_URL".to_string(), sid);
        m1.insert("API_KEY".to_string(), sid);
        let mut m2 = std::collections::BTreeMap::new();
        m2.insert("API_KEY".to_string(), sid);
        m2.insert("DB_URL".to_string(), sid);
        let s1 = base(m1);
        let s2 = base(m2);
        // A BTreeMap is inherently ordered: insertion order affects neither
        // equality nor the canonical id.
        assert_eq!(s1, s2);
        assert_eq!(s1.id(), s2.id());
        assert_eq!(s1, Object::decode(&s1.encode()).unwrap());
    }

    #[test]
    fn snapshot_with_protection_roundtrips_canonically() {
        let root = Object::blob(b"r".to_vec()).id();
        let cid = Object::blob(b"ct".to_vec()).id();
        let mut wrapped = std::collections::BTreeMap::new();
        wrapped.insert(
            cid,
            vec![WrappedKey {
                recipient_id: "rid".into(),
                wrapped_dek: vec![7; 80],
            }],
        );
        let prot = Protection {
            prefixes: vec![ProtectPrefix {
                prefix: "secrets/".into(),
                recipients: vec![RecipientEntry {
                    key: [9u8; 32],
                    epoch: 1,
                    state: RecipientState::Granted,
                }],
            }],
            wrapped,
        };
        let snap = Object::Snapshot(Snapshot {
            root,
            parents: vec![],
            author: "a".into(),
            timestamp: 0,
            message: "m".into(),
            secrets: std::collections::BTreeMap::new(),
            protection: prot,
        });
        assert_eq!(snap, Object::decode(&snap.encode()).unwrap());
    }

    #[test]
    fn protection_recipients_order_independent_id() {
        let root = Object::blob(b"r".to_vec()).id();
        let a = RecipientEntry {
            key: [1u8; 32],
            epoch: 1,
            state: RecipientState::Granted,
        };
        let b = RecipientEntry {
            key: [2u8; 32],
            epoch: 1,
            state: RecipientState::Granted,
        };
        let snap = |recipients: Vec<RecipientEntry>| {
            Object::Snapshot(Snapshot {
                root,
                parents: vec![],
                author: "a".into(),
                timestamp: 0,
                message: "m".into(),
                secrets: std::collections::BTreeMap::new(),
                protection: Protection {
                    prefixes: vec![ProtectPrefix {
                        prefix: "secrets/".into(),
                        recipients,
                    }],
                    wrapped: std::collections::BTreeMap::new(),
                },
            })
        };
        // Same recipient set, opposite order -> identical canonical id.
        assert_eq!(snap(vec![a.clone(), b.clone()]).id(), snap(vec![b, a]).id());
    }

    #[test]
    fn snapshot_roundtrips_recipient_registers_and_tombstones() {
        let snap = Snapshot {
            root: ObjectId::from_bytes([1; 32]),
            parents: vec![],
            author: "a".into(),
            timestamp: 0,
            message: "m".into(),
            secrets: Default::default(),
            protection: Protection {
                prefixes: vec![ProtectPrefix {
                    prefix: "secret/".into(),
                    recipients: vec![
                        RecipientEntry {
                            key: [2; 32],
                            epoch: 3,
                            state: RecipientState::Granted,
                        },
                        RecipientEntry {
                            key: [1; 32],
                            epoch: 2,
                            state: RecipientState::Revoked,
                        },
                    ],
                }],
                wrapped: Default::default(),
            },
        };
        let bytes = Object::Snapshot(snap.clone()).encode();
        let Object::Snapshot(back) = Object::decode(&bytes).unwrap() else {
            panic!("not a snapshot")
        };
        // Entries round-trip, sorted by key in the encoding.
        let rule = &back.protection.prefixes[0];
        assert_eq!(rule.recipients.len(), 2);
        let revoked = rule.recipients.iter().find(|e| e.key == [1; 32]).unwrap();
        assert_eq!((revoked.epoch, revoked.state), (2, RecipientState::Revoked));
        let granted = rule.recipients.iter().find(|e| e.key == [2; 32]).unwrap();
        assert_eq!((granted.epoch, granted.state), (3, RecipientState::Granted));
    }

    #[test]
    fn recipient_entry_order_does_not_change_snapshot_id() {
        let mk = |entries: Vec<RecipientEntry>| {
            Object::Snapshot(Snapshot {
                root: ObjectId::from_bytes([1; 32]),
                parents: vec![],
                author: "a".into(),
                timestamp: 0,
                message: "m".into(),
                secrets: Default::default(),
                protection: Protection {
                    prefixes: vec![ProtectPrefix {
                        prefix: "secret/".into(),
                        recipients: entries,
                    }],
                    wrapped: Default::default(),
                },
            })
            .id()
        };
        let e1 = RecipientEntry {
            key: [1; 32],
            epoch: 1,
            state: RecipientState::Granted,
        };
        let e2 = RecipientEntry {
            key: [2; 32],
            epoch: 2,
            state: RecipientState::Revoked,
        };
        assert_eq!(mk(vec![e1.clone(), e2.clone()]), mk(vec![e2, e1]));
    }

    #[test]
    fn pre_p16_snapshot_tag_fails_with_clear_error() {
        // Tag 2 was the pre-P16 snapshot encoding. It must be refused loudly,
        // not misparsed into garbage.
        let err = Object::decode(&[2u8, 0, 0]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("pre-P16"), "unhelpful error: {msg}");
    }

    #[test]
    fn signature_object_roundtrips() {
        let sig_obj = Object::Signature(SignatureObj {
            snapshot: ObjectId::from_bytes([3; 32]),
            signer: [5; 32],
            sig: [9; 64],
        });
        assert_eq!(sig_obj, Object::decode(&sig_obj.encode()).unwrap());
        assert_eq!(sig_obj.kind_name(), "signature");
    }

    #[test]
    fn signature_object_ids_are_content_addressed() {
        // Same fields -> same id; a different signer or sig byte changes it.
        let a = Object::Signature(SignatureObj {
            snapshot: ObjectId::from_bytes([1; 32]),
            signer: [2; 32],
            sig: [3; 64],
        });
        let b = Object::Signature(SignatureObj {
            snapshot: ObjectId::from_bytes([1; 32]),
            signer: [2; 32],
            sig: [3; 64],
        });
        assert_eq!(a.id(), b.id());
        let c = Object::Signature(SignatureObj {
            snapshot: ObjectId::from_bytes([1; 32]),
            signer: [9; 32],
            sig: [3; 64],
        });
        assert_ne!(a.id(), c.id());
    }

    #[test]
    fn signature_decode_rejects_truncation() {
        let sig_obj = Object::Signature(SignatureObj {
            snapshot: ObjectId::from_bytes([3; 32]),
            signer: [5; 32],
            sig: [9; 64],
        });
        let bytes = sig_obj.encode();
        // Chop off the last byte of the fixed-width sig field: too short to
        // decode, must error rather than silently truncate the signature.
        let truncated = &bytes[..bytes.len() - 1];
        assert!(Object::decode(truncated).is_err());
        // Trailing garbage past the fixed-width fields must also be rejected.
        let mut extended = bytes.clone();
        extended.push(0xff);
        assert!(Object::decode(&extended).is_err());
    }

    #[test]
    fn object_decode_fabricated_counts_rejected() {
        // Each buffer is hand-crafted with a fabricated huge u32 count
        // (0xFFFF_FFFF) as the LAST bytes, with nothing following it — the
        // same idiom Reader::count()'s own doc comment describes: every
        // element consumes at least one byte, so a count exceeding the
        // reader's remaining bytes (here, zero) is fabricated and must be
        // rejected before `Vec::with_capacity(n)` ever runs.
        const HUGE: u32 = 0xFFFF_FFFF;

        // TAG_TREE: tag(1) + entry-count(u32, fabricated), no entries follow.
        let mut tree = vec![TAG_TREE];
        tree.extend_from_slice(&HUGE.to_be_bytes());
        assert!(
            matches!(Object::decode(&tree), Err(Error::Malformed(_))),
            "tree"
        );

        // TAG_SNAPSHOT parents: tag(4) + root id(32) + parents-count(u32, fabricated).
        let mut snap_parents = vec![TAG_SNAPSHOT];
        snap_parents.extend_from_slice(&[0u8; 32]); // root
        snap_parents.extend_from_slice(&HUGE.to_be_bytes());
        assert!(
            matches!(Object::decode(&snap_parents), Err(Error::Malformed(_))),
            "snapshot parents"
        );

        // TAG_SNAPSHOT secrets: tag(4) + root(32) + parents-count(0) + author
        // str(0) + timestamp(8) + message str(0) + secrets-count(u32, fabricated).
        let mut snap_secrets = vec![TAG_SNAPSHOT];
        snap_secrets.extend_from_slice(&[0u8; 32]); // root
        snap_secrets.extend_from_slice(&0u32.to_be_bytes()); // parents count
        snap_secrets.extend_from_slice(&0u32.to_be_bytes()); // author str len
        snap_secrets.extend_from_slice(&0i64.to_be_bytes()); // timestamp
        snap_secrets.extend_from_slice(&0u32.to_be_bytes()); // message str len
        snap_secrets.extend_from_slice(&HUGE.to_be_bytes()); // secrets count
        assert!(
            matches!(Object::decode(&snap_secrets), Err(Error::Malformed(_))),
            "snapshot secrets"
        );

        // TAG_SECRET wrapped_keys: tag(3) + name str(0) + nonce bytes(0) +
        // ciphertext bytes(0) + wrapped_keys-count(u32, fabricated).
        let mut secret = vec![TAG_SECRET];
        secret.extend_from_slice(&0u32.to_be_bytes()); // name str len
        secret.extend_from_slice(&0u32.to_be_bytes()); // nonce len
        secret.extend_from_slice(&0u32.to_be_bytes()); // ciphertext len
        secret.extend_from_slice(&HUGE.to_be_bytes()); // wrapped_keys count
        assert!(
            matches!(Object::decode(&secret), Err(Error::Malformed(_))),
            "secret wrapped_keys"
        );
    }

    #[test]
    fn transcript_round_trips_and_id_is_stable() {
        let t = Transcript {
            snapshot: ObjectId::of(b"snap"),
            agent: "claude-code".into(),
            session: "sess-42".into(),
            nonce: vec![1, 2, 3],
            ciphertext: vec![9, 8, 7, 6],
            wrapped_keys: vec![WrappedKey {
                recipient_id: "rid".into(),
                wrapped_dek: vec![4, 5],
            }],
        };
        let obj = Object::Transcript(t.clone());
        let bytes = obj.encode();
        let back = Object::decode(&bytes).unwrap();
        assert_eq!(back, obj);
        // id-stability: same content encodes byte-identically → same id.
        assert_eq!(
            ObjectId::of(&bytes),
            ObjectId::of(&Object::Transcript(t).encode())
        );
    }

    #[test]
    fn transcript_decode_rejects_fabricated_wrap_count() {
        // TAG_TRANSCRIPT(6) + snapshot(32) + agent str(0) + session str(0)
        // + nonce bytes(0) + ciphertext bytes(0) + wrap-count = 0xFFFF_FFFF, no wraps.
        let mut buf = vec![6u8];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&0u32.to_be_bytes()); // agent len
        buf.extend_from_slice(&0u32.to_be_bytes()); // session len
        buf.extend_from_slice(&0u32.to_be_bytes()); // nonce len
        buf.extend_from_slice(&0u32.to_be_bytes()); // ciphertext len
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // wrap count
        assert!(matches!(Object::decode(&buf), Err(Error::Malformed(_))));
    }

    #[test]
    fn granted_keys_next_epoch_set_standing() {
        let mut rule = ProtectPrefix {
            prefix: "secret/".into(),
            recipients: vec![],
        };
        assert_eq!(rule.next_epoch(), 1);
        rule.set_standing([1; 32], 1, RecipientState::Granted);
        rule.set_standing([2; 32], 1, RecipientState::Granted);
        assert_eq!(rule.next_epoch(), 2);
        rule.set_standing([2; 32], 2, RecipientState::Revoked); // upsert, not append
        assert_eq!(rule.recipients.len(), 2);
        assert_eq!(rule.granted_keys(), vec![[1; 32]]);
        assert_eq!(rule.next_epoch(), 3);
    }

    #[test]
    fn sealed_object_roundtrips_and_differs_from_blob() {
        let payload: Vec<u8> = (0..64).collect();
        let sealed = Object::Sealed(SealedObj {
            payload: Arc::from(payload.clone().into_boxed_slice()),
        });
        assert_eq!(sealed, Object::decode(&sealed.encode()).unwrap());
        assert_eq!(sealed.kind_name(), "sealed");
        assert_eq!(sealed.blob_size(), 64, "sealed bytes are budget-counted");
        // Same bytes as a plain blob must hash to a DIFFERENT id: the tag is
        // part of the encoding, so ciphertext can never collide with a
        // plaintext blob's address.
        assert_ne!(sealed.id(), Object::blob(payload).id());
    }

    #[test]
    fn manifest_roundtrips_and_closure_is_order_independent() {
        let a = ObjectId::from_bytes([1; 32]);
        let b = ObjectId::from_bytes([2; 32]);
        let mk = |closure: Vec<ObjectId>| {
            Object::Manifest(BranchManifest {
                base: ObjectId::from_bytes([9; 32]),
                prev: Some(ObjectId::from_bytes([8; 32])),
                anchors: vec![ObjectId::from_bytes([7; 32])],
                closure,
                index_ct: vec![7; 40],
                kek_wraps: vec![WrappedKey {
                    recipient_id: "rid".into(),
                    wrapped_dek: vec![5; 80],
                }],
            })
        };
        let m1 = mk(vec![a, b]);
        let m2 = mk(vec![b, a]);
        assert_eq!(m1.id(), m2.id(), "closure order must not change the id");
        let decoded = Object::decode(&m1.encode()).unwrap();
        let Object::Manifest(back) = decoded else {
            panic!("not a manifest")
        };
        assert_eq!(back.base, ObjectId::from_bytes([9; 32]));
        assert_eq!(back.closure, vec![a, b], "decoded closure is sorted");
        assert_eq!(back.index_ct, vec![7; 40]);
        assert_eq!(back.kek_wraps.len(), 1);
    }

    #[test]
    fn manifest_decode_rejects_fabricated_counts() {
        const HUGE: u32 = 0xFFFF_FFFF;
        // TAG_MANIFEST + base(32) + prev(0) + anchor-count(fabricated).
        let mut buf = vec![TAG_MANIFEST];
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0u8); // prev marker: none
        buf.extend_from_slice(&HUGE.to_be_bytes());
        assert!(matches!(Object::decode(&buf), Err(Error::Malformed(_))));
        // Same for the kek-wrap count after empty anchors + closure + index.
        let mut buf = vec![TAG_MANIFEST];
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0u8); // prev marker: none
        buf.extend_from_slice(&0u32.to_be_bytes()); // anchor count
        buf.extend_from_slice(&0u32.to_be_bytes()); // closure count
        buf.extend_from_slice(&0u32.to_be_bytes()); // index_ct len
        buf.extend_from_slice(&HUGE.to_be_bytes()); // kek wrap count
        assert!(matches!(Object::decode(&buf), Err(Error::Malformed(_))));
    }

    #[test]
    fn randomized_bit_is_distinct_from_protected() {
        assert_eq!(PROTECTED & RANDOMIZED, 0, "flags must not overlap");
        assert_ne!(RANDOMIZED, 0);
        // A randomized entry is always also protected.
        let perms = PROTECTED | RANDOMIZED;
        assert!(perms & PROTECTED != 0 && perms & RANDOMIZED != 0);
    }
}

/// Property tests for the canonical encoding — the content-addressing
/// invariant (same logical content ⇒ same id on any machine) and decode
/// totality on attacker-supplied bytes. `encode` canonicalizes (sorts
/// protection registers, manifest anchors/closure), so the load-bearing
/// property is encode-stability through a decode round trip, not strict
/// struct equality.
#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_id() -> impl Strategy<Value = ObjectId> {
        any::<[u8; 32]>().prop_map(ObjectId::from_bytes)
    }

    fn arb_wrapped_key() -> impl Strategy<Value = WrappedKey> {
        (".{0,16}", proptest::collection::vec(any::<u8>(), 0..64)).prop_map(
            |(recipient_id, wrapped_dek)| WrappedKey {
                recipient_id,
                wrapped_dek,
            },
        )
    }

    fn arb_tree() -> impl Strategy<Value = Tree> {
        proptest::collection::vec(
            (
                ".{0,12}",
                any::<bool>(),
                arb_id(),
                any::<u32>(),
                any::<u8>(),
            ),
            0..8,
        )
        .prop_map(|es| {
            Tree::new(
                es.into_iter()
                    .map(|(name, is_tree, id, mode, perms)| TreeEntry {
                        name,
                        kind: if is_tree {
                            EntryKind::Tree
                        } else {
                            EntryKind::Blob
                        },
                        id,
                        mode: FileMode(mode),
                        perms,
                    })
                    .collect(),
            )
        })
    }

    fn arb_protection() -> impl Strategy<Value = Protection> {
        (
            proptest::collection::vec(
                (
                    ".{0,12}",
                    proptest::collection::vec(
                        (any::<[u8; 32]>(), any::<u32>(), any::<bool>()),
                        0..4,
                    ),
                ),
                0..4,
            ),
            proptest::collection::btree_map(
                arb_id(),
                proptest::collection::vec(arb_wrapped_key(), 0..3),
                0..4,
            ),
        )
            .prop_map(|(prefixes, wrapped)| Protection {
                prefixes: prefixes
                    .into_iter()
                    .map(|(prefix, recipients)| ProtectPrefix {
                        prefix,
                        recipients: recipients
                            .into_iter()
                            .map(|(key, epoch, granted)| RecipientEntry {
                                key,
                                epoch,
                                state: if granted {
                                    RecipientState::Granted
                                } else {
                                    RecipientState::Revoked
                                },
                            })
                            .collect(),
                    })
                    .collect(),
                wrapped,
            })
    }

    fn arb_snapshot() -> impl Strategy<Value = Snapshot> {
        (
            arb_id(),
            proptest::collection::vec(arb_id(), 0..4),
            ".{0,20}",
            any::<i64>(),
            ".{0,40}",
            proptest::collection::btree_map(".{0,12}", arb_id(), 0..4),
            arb_protection(),
        )
            .prop_map(
                |(root, parents, author, timestamp, message, secrets, protection)| Snapshot {
                    root,
                    parents,
                    author,
                    timestamp,
                    message,
                    secrets,
                    protection,
                },
            )
    }

    fn arb_manifest() -> impl Strategy<Value = BranchManifest> {
        (
            arb_id(),
            proptest::option::of(arb_id()),
            proptest::collection::vec(arb_id(), 0..4),
            proptest::collection::vec(arb_id(), 0..6),
            proptest::collection::vec(any::<u8>(), 0..64),
            proptest::collection::vec(arb_wrapped_key(), 0..3),
        )
            .prop_map(|(base, prev, anchors, closure, index_ct, kek_wraps)| {
                BranchManifest {
                    base,
                    prev,
                    anchors,
                    closure,
                    index_ct,
                    kek_wraps,
                }
            })
    }

    fn arb_object() -> impl Strategy<Value = Object> {
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..256).prop_map(Object::blob),
            arb_tree().prop_map(Object::Tree),
            arb_snapshot().prop_map(Object::Snapshot),
            (
                ".{0,16}",
                proptest::collection::vec(any::<u8>(), 0..32),
                proptest::collection::vec(any::<u8>(), 0..128),
                proptest::collection::vec(arb_wrapped_key(), 0..3),
            )
                .prop_map(|(name, nonce, ciphertext, wrapped_keys)| {
                    Object::Secret(Secret {
                        name,
                        nonce,
                        ciphertext,
                        wrapped_keys,
                    })
                }),
            (arb_id(), any::<[u8; 32]>(), any::<[u8; 64]>()).prop_map(|(snapshot, signer, sig)| {
                Object::Signature(SignatureObj {
                    snapshot,
                    signer,
                    sig,
                })
            }),
            (
                arb_id(),
                ".{0,12}",
                ".{0,12}",
                proptest::collection::vec(any::<u8>(), 0..32),
                proptest::collection::vec(any::<u8>(), 0..128),
                proptest::collection::vec(arb_wrapped_key(), 0..3),
            )
                .prop_map(
                    |(snapshot, agent, session, nonce, ciphertext, wrapped_keys)| {
                        Object::Transcript(Transcript {
                            snapshot,
                            agent,
                            session,
                            nonce,
                            ciphertext,
                            wrapped_keys,
                        })
                    }
                ),
            proptest::collection::vec(any::<u8>(), 0..256).prop_map(|p| Object::Sealed(
                SealedObj {
                    payload: Arc::from(p.into_boxed_slice()),
                }
            )),
            arb_manifest().prop_map(Object::Manifest),
        ]
    }

    proptest! {
        /// decode(encode(o)) succeeds, re-encodes to the identical bytes, and
        /// keeps the content address — the core invariant in CLAUDE.md.
        #[test]
        fn decode_of_own_encoding_is_id_stable(o in arb_object()) {
            let bytes = o.encode();
            let decoded = Object::decode(&bytes).expect("own encoding must decode");
            prop_assert_eq!(decoded.encode(), bytes);
            prop_assert_eq!(decoded.id(), o.id());
        }

        /// decode is total on arbitrary bytes: Ok or Err, never a panic —
        /// this is the path attacker-supplied wire/pack data reaches.
        #[test]
        fn decode_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let _ = Object::decode(&bytes);
        }

        /// decode is total on truncations of valid encodings — the malformed
        /// input most likely to occur in practice (cut-off transfers).
        #[test]
        fn decode_never_panics_on_truncated_encodings(
            o in arb_object(),
            cut in any::<prop::sample::Index>()
        ) {
            let bytes = o.encode();
            let cut = cut.index(bytes.len() + 1);
            let _ = Object::decode(&bytes[..cut.min(bytes.len())]);
        }
    }
}
