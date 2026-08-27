//! On-bucket WAL encoding (P36a). Versioned, strict, fail-closed: readers
//! refuse unknown versions and any length that overruns the buffer.

use crate::error::{Error, Result};
use scl_core::ObjectId;

const MANIFEST_MAGIC: &[u8; 4] = b"SCWM";
const ENTRY_MAGIC: &[u8; 4] = b"SCWE";
const CHECKPOINT_MAGIC: &[u8; 4] = b"SCWC";
const VERSION: u32 = 1;
const MAX_NAME: usize = 4096;
/// Cap on the number of entries in any length-prefixed list this format
/// encodes (a `LogEntry`'s `packs`/`updates`, a `Checkpoint`'s `refs`/
/// `packs`). `pub(crate)` so `bucket_transport`'s checkpoint fold can check
/// against the same cap `Checkpoint::decode` enforces, rather than
/// duplicating the literal — see `maybe_fold_checkpoint`'s guard.
pub(crate) const MAX_LIST: usize = 65536;
const MAX_HASH: usize = 128;

/// A bounds-checked cursor over a decode buffer. Every read either advances
/// `at` by exactly what it consumed or returns an error — callers never see
/// a partially-advanced cursor after a failure.
struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() - self.at < n {
            return Err(Error::Wal(format!("truncated at byte {}", self.at)));
        }
        let s = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn string(&mut self, cap: usize) -> Result<String> {
        let n = self.u32()? as usize;
        if n > cap {
            return Err(Error::Wal(format!("length {n} exceeds cap {cap}")));
        }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| Error::Wal("non-utf8 name".into()))
    }

    fn id(&mut self) -> Result<ObjectId> {
        let raw: [u8; 32] = self.take(32)?.try_into().unwrap();
        Ok(ObjectId::from_bytes(raw))
    }

    fn done(&self) -> Result<()> {
        if self.at != self.buf.len() {
            return Err(Error::Wal(format!(
                "{} trailing bytes",
                self.buf.len() - self.at
            )));
        }
        Ok(())
    }
}

/// Parse and validate the 8-byte magic+version header, returning a cursor
/// positioned right after it. Unknown versions are refused (fail closed).
fn header<'a>(bytes: &'a [u8], magic: &[u8; 4], what: &str) -> Result<Cursor<'a>> {
    let mut c = Cursor { buf: bytes, at: 0 };
    if c.take(4)? != magic {
        return Err(Error::Wal(format!("not a {what} (bad magic)")));
    }
    let v = c.u32()?;
    if v != VERSION {
        return Err(Error::Wal(format!(
            "{what} version {v} not supported (this build speaks {VERSION})"
        )));
    }
    Ok(c)
}

fn push_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// The bucket-remote WAL's root pointer: current head sequence, the last
/// checkpoint sequence (a future compaction cutoff), and which branch the
/// head points at. One manifest object per remote, overwritten on every
/// successful append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub head_seq: u64,
    pub checkpoint_seq: u64,
    pub head_branch: String,
}

impl Manifest {
    /// Serialize to the on-bucket wire format: magic, version, then fields
    /// in declaration order, all little-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MANIFEST_MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.head_seq.to_le_bytes());
        out.extend_from_slice(&self.checkpoint_seq.to_le_bytes());
        push_string(&mut out, &self.head_branch);
        out
    }

    /// Strictly decode a manifest: bad magic, unknown version, any length
    /// that overruns the buffer, or trailing bytes are all refused.
    pub fn decode(bytes: &[u8]) -> Result<Manifest> {
        let mut c = header(bytes, MANIFEST_MAGIC, "manifest")?;
        let head_seq = c.u64()?;
        let checkpoint_seq = c.u64()?;
        let head_branch = c.string(MAX_NAME)?;
        c.done()?;
        Ok(Manifest {
            head_seq,
            checkpoint_seq,
            head_branch,
        })
    }
}

/// One branch-ref move recorded in a [`LogEntry`]. `old` is `None` for a
/// branch that was unborn before this entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub branch: String,
    pub old: Option<ObjectId>,
    pub new: ObjectId,
}

/// One append-only WAL record: the pack(s) it introduces and the ref moves
/// that became visible once those packs landed. `parent_seq` chains entries
/// so a reader can detect a gap (a missing predecessor) without listing the
/// whole bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub seq: u64,
    pub parent_seq: u64,
    pub packs: Vec<String>,
    pub updates: Vec<RefUpdate>,
}

impl LogEntry {
    /// Serialize to the on-bucket wire format: magic, version, seq fields,
    /// then length-prefixed pack names and ref updates, all little-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ENTRY_MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.parent_seq.to_le_bytes());
        out.extend_from_slice(&(self.packs.len() as u32).to_le_bytes());
        for pack in &self.packs {
            push_string(&mut out, pack);
        }
        out.extend_from_slice(&(self.updates.len() as u32).to_le_bytes());
        for update in &self.updates {
            push_string(&mut out, &update.branch);
            match &update.old {
                Some(id) => {
                    out.push(1);
                    out.extend_from_slice(id.as_bytes());
                }
                None => out.push(0),
            }
            out.extend_from_slice(update.new.as_bytes());
        }
        out
    }

    /// Strictly decode a log entry: every length is bounds-checked against
    /// the cap and the remaining buffer; unknown version or trailing bytes
    /// are refused.
    pub fn decode(bytes: &[u8]) -> Result<LogEntry> {
        let mut c = header(bytes, ENTRY_MAGIC, "log entry")?;
        let seq = c.u64()?;
        let parent_seq = c.u64()?;

        let npacks = c.u32()? as usize;
        if npacks > MAX_LIST {
            return Err(Error::Wal(format!("{npacks} packs exceeds cap {MAX_LIST}")));
        }
        let mut packs = Vec::with_capacity(npacks);
        for _ in 0..npacks {
            packs.push(c.string(MAX_HASH)?);
        }

        let nupdates = c.u32()? as usize;
        if nupdates > MAX_LIST {
            return Err(Error::Wal(format!(
                "{nupdates} updates exceeds cap {MAX_LIST}"
            )));
        }
        let mut updates = Vec::with_capacity(nupdates);
        for _ in 0..nupdates {
            let branch = c.string(MAX_NAME)?;
            let has_old = c.u8()?;
            let old = match has_old {
                0 => None,
                1 => Some(c.id()?),
                other => return Err(Error::Wal(format!("bad has_old flag: {other}"))),
            };
            let new = c.id()?;
            updates.push(RefUpdate { branch, old, new });
        }

        c.done()?;
        Ok(LogEntry {
            seq,
            parent_seq,
            packs,
            updates,
        })
    }
}

/// A fold of the WAL at `seq`: every branch tip and every on-chain pack hash
/// accumulated from the chain's start through log entry `seq`. Cold start =
/// this + the log tail after `seq`, instead of replaying the whole chain.
/// Referenced (and made authoritative) only by `Manifest.checkpoint_seq`;
/// an unreferenced checkpoint object is garbage like any off-chain key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub seq: u64,
    /// branch -> tip pairs, sorted by branch (BTreeMap iteration order).
    pub refs: Vec<(String, ObjectId)>,
    /// Cumulative pack hashes in chain order (oldest first).
    pub packs: Vec<String>,
}

impl Checkpoint {
    /// Serialize to the on-bucket wire format: magic, version, then fields
    /// in declaration order, all little-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CHECKPOINT_MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&(self.refs.len() as u32).to_le_bytes());
        for (branch, id) in &self.refs {
            push_string(&mut out, branch);
            out.extend_from_slice(id.as_bytes());
        }
        out.extend_from_slice(&(self.packs.len() as u32).to_le_bytes());
        for hash in &self.packs {
            push_string(&mut out, hash);
        }
        out
    }

    /// Strictly decode a checkpoint: bad magic, unknown version, any length
    /// that overruns the buffer, or trailing bytes are all refused.
    pub fn decode(bytes: &[u8]) -> Result<Checkpoint> {
        let mut c = header(bytes, CHECKPOINT_MAGIC, "checkpoint")?;
        let seq = c.u64()?;
        let nrefs = c.u32()? as usize;
        if nrefs > MAX_LIST {
            return Err(Error::Wal(format!(
                "checkpoint ref count {nrefs} exceeds cap"
            )));
        }
        let mut refs = Vec::with_capacity(nrefs);
        for _ in 0..nrefs {
            let branch = c.string(MAX_NAME)?;
            let id = c.id()?;
            refs.push((branch, id));
        }
        let npacks = c.u32()? as usize;
        if npacks > MAX_LIST {
            return Err(Error::Wal(format!(
                "checkpoint pack count {npacks} exceeds cap"
            )));
        }
        let mut packs = Vec::with_capacity(npacks);
        for _ in 0..npacks {
            packs.push(c.string(MAX_HASH)?);
        }
        c.done()?;
        Ok(Checkpoint { seq, refs, packs })
    }
}

/// `log/<seq>` zero-padded so lexical order == numeric order.
pub fn log_key(seq: u64) -> String {
    format!("log/{seq:020}")
}

/// `checkpoints/<seq>` zero-padded so lexical order == numeric order.
pub fn checkpoint_key(seq: u64) -> String {
    format!("checkpoints/{seq:020}")
}

/// `packs/<hash>.pack` — the packfile object for a given content hash.
pub fn pack_key(hash: &str) -> String {
    format!("packs/{hash}.pack")
}

/// `packs/<hash>.idx` — the index object accompanying [`pack_key`]'s pack.
pub fn idx_key(hash: &str) -> String {
    format!("packs/{hash}.idx")
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::ObjectId;

    fn some_id(byte: u8) -> ObjectId {
        // Any real id: hash a one-byte payload. Use whatever constructor
        // refs::read_branch_tip uses to parse hex tips (check refs.rs:35 and
        // reuse the identical call) — or simplest: ObjectId::of(&[byte]).
        ObjectId::of(&[byte])
    }

    #[test]
    fn manifest_round_trips_and_rejects_garbage() {
        let m = Manifest {
            head_seq: 7,
            checkpoint_seq: 0,
            head_branch: "main".into(),
        };
        let bytes = m.encode();
        let back = Manifest::decode(&bytes).unwrap();
        assert_eq!(back.head_seq, 7);
        assert_eq!(back.checkpoint_seq, 0);
        assert_eq!(back.head_branch, "main");
        // wrong magic, truncated, future version, trailing junk: all refused
        assert!(Manifest::decode(b"XXXX").is_err());
        assert!(Manifest::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut future = bytes.clone();
        future[4] = 0xFF; // bump version byte
        assert!(Manifest::decode(&future).is_err());
        let mut junk = bytes.clone();
        junk.push(0);
        assert!(Manifest::decode(&junk).is_err());
    }

    #[test]
    fn log_entry_round_trips_with_and_without_old_tips() {
        let e = LogEntry {
            seq: 3,
            parent_seq: 2,
            packs: vec!["ab12".into()],
            updates: vec![
                RefUpdate {
                    branch: "main".into(),
                    old: Some(some_id(1)),
                    new: some_id(2),
                },
                RefUpdate {
                    branch: "feat".into(),
                    old: None,
                    new: some_id(3),
                },
            ],
        };
        let back = LogEntry::decode(&e.encode()).unwrap();
        assert_eq!(back.seq, 3);
        assert_eq!(back.parent_seq, 2);
        assert_eq!(back.packs, vec!["ab12".to_string()]);
        assert_eq!(back.updates.len(), 2);
        assert_eq!(back.updates[0].old, Some(some_id(1)));
        assert_eq!(back.updates[1].old, None);
        assert_eq!(back.updates[1].new, some_id(3));
    }

    #[test]
    fn decode_caps_hostile_lengths() {
        // a length prefix claiming 1 GiB must fail fast, not allocate
        let mut evil = Manifest {
            head_seq: 1,
            checkpoint_seq: 0,
            head_branch: "m".into(),
        }
        .encode();
        let n = evil.len();
        evil[n - 2..].copy_from_slice(&[0xFF, 0xFF]); // corrupt branch length tail
        assert!(Manifest::decode(&evil).is_err());
    }

    #[test]
    fn keys_are_stable() {
        assert_eq!(log_key(7), "log/00000000000000000007");
        assert_eq!(pack_key("abcd"), "packs/abcd.pack");
        assert_eq!(idx_key("abcd"), "packs/abcd.idx");
    }

    #[test]
    fn checkpoint_round_trips_and_rejects_garbage() {
        let c = Checkpoint {
            seq: 64,
            refs: vec![
                ("feat".to_string(), some_id(2)),
                ("main".to_string(), some_id(1)),
            ],
            packs: vec!["ab12".to_string(), "cd34".to_string()],
        };
        let bytes = c.encode();
        assert_eq!(Checkpoint::decode(&bytes).unwrap(), c);
        // wrong magic, truncated, future version, trailing junk: refused
        assert!(Checkpoint::decode(b"XXXX").is_err());
        assert!(Checkpoint::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut future = bytes.clone();
        future[4] = 0xFF;
        assert!(Checkpoint::decode(&future).is_err());
        let mut junk = bytes.clone();
        junk.push(0);
        assert!(Checkpoint::decode(&junk).is_err());
        // a log-entry buffer is not a checkpoint (magic mismatch, not a panic)
        let entry = LogEntry {
            seq: 1,
            parent_seq: 0,
            packs: vec![],
            updates: vec![],
        };
        assert!(Checkpoint::decode(&entry.encode()).is_err());
    }

    #[test]
    fn checkpoint_decode_caps_hostile_counts() {
        // corrupt the refs count to u32::MAX: must fail fast, not allocate
        let c = Checkpoint {
            seq: 1,
            refs: vec![("m".to_string(), some_id(1))],
            packs: vec![],
        };
        let mut evil = c.encode();
        // refs count sits right after magic(4)+version(4)+seq(8) = offset 16
        evil[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Checkpoint::decode(&evil).is_err());
    }

    #[test]
    fn checkpoint_key_is_stable() {
        assert_eq!(checkpoint_key(64), "checkpoints/00000000000000000064");
    }
}
