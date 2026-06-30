//! Object model and canonical serialization.
//!
//! Every object is serialized to a deterministic byte form whose BLAKE3 hash is
//! its [`ObjectId`]. The encoding is length-prefixed and tree entries are sorted,
//! so the same logical content always produces the same address on any machine.

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::id::ObjectId;

/// Object kind tags, written as the first byte of every encoding.
const TAG_BLOB: u8 = 0;
const TAG_TREE: u8 = 1;
const TAG_SNAPSHOT: u8 = 2;
const TAG_SECRET: u8 = 3;

/// Perms-byte bit: this blob entry holds a `nonce‖ciphertext` envelope (an
/// encrypted file), not plaintext. Set on protected-path entries (P7).
pub const PROTECTED: u8 = 0b0000_0001;

/// A protected path prefix and the recipient public keys its files are
/// encrypted for (used at commit time to wrap new files' DEKs).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProtectPrefix {
    pub prefix: String,
    pub recipients: Vec<[u8; 32]>,
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

/// Any object the store can hold. Blob bytes are `Arc`-shared so forking many
/// worktrees off one snapshot never copies file content.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Object {
    Blob(Arc<[u8]>),
    Tree(Tree),
    Snapshot(Snapshot),
    Secret(Secret),
}

impl Object {
    pub fn blob(bytes: impl Into<Vec<u8>>) -> Object {
        Object::Blob(Arc::from(bytes.into().into_boxed_slice()))
    }

    /// Bytes counted against the store's blob budget (0 for non-blobs).
    pub fn blob_size(&self) -> usize {
        match self {
            Object::Blob(b) => b.len(),
            _ => 0,
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Object::Blob(_) => "blob",
            Object::Tree(_) => "tree",
            Object::Snapshot(_) => "snapshot",
            Object::Secret(_) => "secret",
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
                    // Sort recipients so the same logical policy hashes
                    // identically regardless of the order they were added in.
                    let mut sorted = p.recipients.clone();
                    sorted.sort_unstable();
                    for r in &sorted {
                        w.raw(r); // 32 bytes
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
        }
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Result<Object> {
        let mut r = Reader::new(bytes);
        let tag = r.u8()?;
        let obj = match tag {
            TAG_BLOB => Object::Blob(Arc::from(r.rest())),
            TAG_TREE => {
                let n = r.u32()?;
                let mut entries = Vec::with_capacity(n as usize);
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
                    entries.push(TreeEntry { name, kind, id, mode, perms });
                }
                Object::Tree(Tree { entries })
            }
            TAG_SNAPSHOT => {
                let root = r.id()?;
                let np = r.u32()?;
                let mut parents = Vec::with_capacity(np as usize);
                for _ in 0..np {
                    parents.push(r.id()?);
                }
                let author = r.str()?;
                let timestamp = r.i64()?;
                let message = r.str()?;
                let ns = r.u32()?;
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
                        recipients.push(rk);
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
                        wks.push(WrappedKey { recipient_id, wrapped_dek });
                    }
                    wrapped.insert(id, wks);
                }
                let protection = Protection { prefixes, wrapped };
                Object::Snapshot(Snapshot { root, parents, author, timestamp, message, secrets, protection })
            }
            TAG_SECRET => {
                let name = r.str()?;
                let nonce = r.bytes()?;
                let ciphertext = r.bytes()?;
                let nk = r.u32()?;
                let mut wrapped_keys = Vec::with_capacity(nk as usize);
                for _ in 0..nk {
                    let recipient_id = r.str()?;
                    let wrapped_dek = r.bytes()?;
                    wrapped_keys.push(WrappedKey { recipient_id, wrapped_dek });
                }
                Object::Secret(Secret { name, nonce, ciphertext, wrapped_keys })
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
            return Err(Error::Malformed("element count exceeds remaining bytes".into()));
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
        wrapped.insert(cid, vec![WrappedKey { recipient_id: "rid".into(), wrapped_dek: vec![7; 80] }]);
        let prot = Protection {
            prefixes: vec![ProtectPrefix { prefix: "secrets/".into(), recipients: vec![[9u8; 32]] }],
            wrapped,
        };
        let snap = Object::Snapshot(Snapshot {
            root, parents: vec![], author: "a".into(), timestamp: 0, message: "m".into(),
            secrets: std::collections::BTreeMap::new(), protection: prot,
        });
        assert_eq!(snap, Object::decode(&snap.encode()).unwrap());
    }

    #[test]
    fn protection_recipients_order_independent_id() {
        let root = Object::blob(b"r".to_vec()).id();
        let a = [1u8; 32];
        let b = [2u8; 32];
        let snap = |recipients: Vec<[u8; 32]>| {
            Object::Snapshot(Snapshot {
                root,
                parents: vec![],
                author: "a".into(),
                timestamp: 0,
                message: "m".into(),
                secrets: std::collections::BTreeMap::new(),
                protection: Protection {
                    prefixes: vec![ProtectPrefix { prefix: "secrets/".into(), recipients }],
                    wrapped: std::collections::BTreeMap::new(),
                },
            })
        };
        // Same recipient set, opposite order -> identical canonical id.
        assert_eq!(snap(vec![a, b]).id(), snap(vec![b, a]).id());
    }
}
