//! Append-only operation log: one block per repo-mutating operation, recording
//! HEAD and every touched local ref before/after. This is the substrate for
//! history editing (undo/redo, `sc op log`) — it never overwrites a prior
//! entry in place; `trim_older_than` is the only operation that rewrites the
//! file, and it always keeps the newest record so there is never a moment
//! with zero history to reconstruct from.
//!
//! On-disk grammar, one block per operation, blank-line separated implicitly
//! by the fixed line count of each block:
//!
//! ```text
//! op <seq>
//! ts <unix-seconds>
//! desc <one line>
//! head <before-name> <after-name>
//! ref <name> <before-hex|-> <after-hex|->
//! end
//! ```
//!
//! Hand-rolled, human-readable parsing (no serde) so the log stays greppable.

use std::fs::OpenOptions;
use std::io::Write as _;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;

/// One logged operation: HEAD and every touched local ref, before/after.
#[derive(Debug, Clone, PartialEq)]
pub struct OpRecord {
    pub seq: u64,
    pub ts: i64,
    pub desc: String,
    /// Symbolic HEAD branch name before/after (equal for most ops).
    pub head_before: String,
    pub head_after: String,
    /// (branch, before, after); None = absent (created/deleted).
    pub refs: Vec<(String, Option<ObjectId>, Option<ObjectId>)>,
}

/// Render one `id` as its grammar token: `-` for absent, hex otherwise.
fn token(id: &Option<ObjectId>) -> String {
    match id {
        Some(id) => id.to_hex(),
        None => "-".to_string(),
    }
}

/// Parse a grammar token back into an optional id. `-` means absent; anything
/// else must be a valid hex `ObjectId`.
fn parse_token(s: &str) -> Option<std::result::Result<ObjectId, ()>> {
    if s == "-" {
        None
    } else {
        Some(s.parse::<ObjectId>().map_err(|_| ()))
    }
}

/// Serialize one record to its on-disk block, trailing newline included.
fn serialize(rec: &OpRecord) -> String {
    let mut out = String::new();
    out.push_str(&format!("op {}\n", rec.seq));
    out.push_str(&format!("ts {}\n", rec.ts));
    // `desc` must not contain a newline — strip any so the one-line-per-field
    // grammar can never be desynchronized by a hostile/careless description.
    let desc = rec.desc.replace('\n', " ");
    out.push_str(&format!("desc {desc}\n"));
    out.push_str(&format!("head {} {}\n", rec.head_before, rec.head_after));
    for (name, before, after) in &rec.refs {
        out.push_str(&format!("ref {name} {} {}\n", token(before), token(after)));
    }
    out.push_str("end\n");
    out
}

/// Append one operation to the log, computing `seq` as one past the current
/// last record (starting at 1) and `ts` via the same unix-seconds helper
/// `repo.rs` uses for snapshot timestamps.
pub(crate) fn record(
    layout: &Layout,
    desc: &str,
    head_before: &str,
    head_after: &str,
    refs: &[(String, Option<ObjectId>, Option<ObjectId>)],
) -> Result<()> {
    let seq = last(layout)?.map(|r| r.seq + 1).unwrap_or(1);
    let rec = OpRecord {
        seq,
        ts: crate::repo::unix_now(),
        desc: desc.to_string(),
        head_before: head_before.to_string(),
        head_after: head_after.to_string(),
        refs: refs.to_vec(),
    };
    let block = serialize(&rec);
    let path = layout.oplog_path();
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(block.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// Parse one block starting at `lines[i]` (must be `"op <seq>"`). Returns the
/// parsed record and the index just past its terminating `end` line, or
/// `None` if the block is malformed in any way (unknown field order, bad
/// hex, missing `end`, etc.) — the caller treats `None` as "stop here,
/// tolerate the rest as a corrupt tail".
fn parse_block(lines: &[&str], i: usize) -> Option<(OpRecord, usize)> {
    let mut i = i;
    let seq: u64 = lines.get(i)?.strip_prefix("op ")?.trim().parse().ok()?;
    i += 1;
    let ts: i64 = lines.get(i)?.strip_prefix("ts ")?.trim().parse().ok()?;
    i += 1;
    let desc = lines.get(i)?.strip_prefix("desc ")?.to_string();
    i += 1;
    let head_line = lines.get(i)?.strip_prefix("head ")?;
    i += 1;
    let mut head_parts = head_line.splitn(2, ' ');
    let head_before = head_parts.next()?.to_string();
    let head_after = head_parts.next()?.to_string();

    let mut refs = Vec::new();
    while let Some(line) = lines.get(i) {
        if let Some(rest) = line.strip_prefix("ref ") {
            let mut parts = rest.splitn(3, ' ');
            let name = parts.next()?.to_string();
            let before_tok = parts.next()?;
            let after_tok = parts.next()?;
            let before = match parse_token(before_tok) {
                None => None,
                Some(Ok(id)) => Some(id),
                Some(Err(())) => return None,
            };
            let after = match parse_token(after_tok) {
                None => None,
                Some(Ok(id)) => Some(id),
                Some(Err(())) => return None,
            };
            refs.push((name, before, after));
            i += 1;
        } else {
            break;
        }
    }

    if lines.get(i)? != &"end" {
        return None;
    }
    i += 1;

    Some((
        OpRecord { seq, ts, desc, head_before, head_after, refs },
        i,
    ))
}

/// Read every well-formed record from the log, in append order. Stops at the
/// first block that fails to parse and returns everything parsed so far —
/// the log is corrupt-tail tolerant, never fatal, so a torn/partial last
/// write (e.g. crash mid-append) doesn't lose the operations recorded before
/// it.
pub(crate) fn read_all(layout: &Layout) -> Result<Vec<OpRecord>> {
    let path = layout.oplog_path();
    let contents = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e)),
    };
    let lines: Vec<&str> = contents.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        match parse_block(&lines, i) {
            Some((rec, next)) => {
                out.push(rec);
                i = next;
            }
            None => break,
        }
    }
    Ok(out)
}

/// The most recently appended well-formed record, if any.
pub(crate) fn last(layout: &Layout) -> Result<Option<OpRecord>> {
    Ok(read_all(layout)?.into_iter().last())
}

/// Drop every record older than `cutoff_ts`, always keeping at least the
/// newest record even if it too predates the cutoff — the log must never be
/// emptied, since some record is always needed as the reconstruction anchor.
/// Rewrites the file atomically (temp file + rename) so a reader never
/// observes a half-written log. Returns the number of records dropped.
pub(crate) fn trim_older_than(layout: &Layout, cutoff_ts: i64) -> Result<usize> {
    let all = read_all(layout)?;
    if all.is_empty() {
        return Ok(0);
    }
    let newest_seq = all.last().expect("checked non-empty above").seq;
    let kept: Vec<OpRecord> = all
        .iter()
        .filter(|r| r.ts >= cutoff_ts || r.seq == newest_seq)
        .cloned()
        .collect();
    let dropped = all.len() - kept.len();
    if dropped > 0 {
        let mut out = String::new();
        for rec in &kept {
            out.push_str(&serialize(rec));
        }
        scl_core::fsutil::atomic_write_durable(&layout.oplog_path(), out.as_bytes())?;
    }
    Ok(dropped)
}

/// Every non-absent object id referenced anywhere in the log (all before/after
/// ids across every record's refs) — used by reachability/GC to keep objects
/// alive that history-editing operations might still need to reconstruct.
pub(crate) fn referenced_ids(layout: &Layout) -> Result<Vec<ObjectId>> {
    let all = read_all(layout)?;
    Ok(all
        .iter()
        .flat_map(|r| r.refs.iter())
        .flat_map(|(_, before, after)| [*before, *after])
        .flatten()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_layout(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("sc-oplog-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        layout
    }

    #[test]
    fn record_and_read_round_trip() {
        let layout = tmp_layout("roundtrip");

        let id1 = ObjectId::of(b"one");
        let id2 = ObjectId::of(b"two");
        record(
            &layout,
            "commit one",
            "main",
            "main",
            &[("main".to_string(), None, Some(id1))],
        )
        .unwrap();
        record(
            &layout,
            "commit two",
            "main",
            "main",
            &[("main".to_string(), Some(id1), Some(id2))],
        )
        .unwrap();

        let all = read_all(&layout).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].seq, 1);
        assert_eq!(all[0].desc, "commit one");
        assert_eq!(all[1].seq, 2);
        assert_eq!(all[1].desc, "commit two");

        let last_rec = last(&layout).unwrap().unwrap();
        assert_eq!(last_rec.seq, 2);
        assert_eq!(last_rec.desc, "commit two");

        let mut ids = referenced_ids(&layout).unwrap();
        ids.sort();
        let mut expected = vec![id1, id1, id2];
        expected.sort();
        assert_eq!(ids, expected);

        std::fs::remove_dir_all(&layout.root).unwrap();
        assert!(!layout.root.exists());
    }

    #[test]
    fn corrupt_tail_is_tolerated_not_fatal() {
        let layout = tmp_layout("corrupt-tail");

        record(&layout, "good op", "main", "main", &[]).unwrap();

        // Append garbage bytes after the one good record.
        let mut f = OpenOptions::new()
            .append(true)
            .open(layout.oplog_path())
            .unwrap();
        f.write_all(b"op x\nnot-a-record\n").unwrap();
        drop(f);

        let all = read_all(&layout).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].desc, "good op");

        let last_rec = last(&layout).unwrap().unwrap();
        assert_eq!(last_rec.desc, "good op");

        std::fs::remove_dir_all(&layout.root).unwrap();
        assert!(!layout.root.exists());
    }

    #[test]
    fn trim_keeps_newest_and_drops_old() {
        let layout = tmp_layout("trim");

        // Record three ops, then hand-adjust their timestamps to 100/200/300
        // by rewriting the log — `record` always uses the real clock.
        record(&layout, "op1", "main", "main", &[]).unwrap();
        record(&layout, "op2", "main", "main", &[]).unwrap();
        record(&layout, "op3", "main", "main", &[]).unwrap();
        let mut all = read_all(&layout).unwrap();
        all[0].ts = 100;
        all[1].ts = 200;
        all[2].ts = 300;
        let rewritten: String = all.iter().map(serialize).collect();
        std::fs::write(layout.oplog_path(), rewritten).unwrap();

        let dropped = trim_older_than(&layout, 250).unwrap();
        assert_eq!(dropped, 2);
        let remaining = read_all(&layout).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].ts, 300);
        assert_eq!(remaining[0].seq, all[2].seq);

        // Trimming past the newest record still leaves it — the log is
        // never emptied.
        let dropped2 = trim_older_than(&layout, 1000).unwrap();
        assert_eq!(dropped2, 0);
        let remaining2 = read_all(&layout).unwrap();
        assert_eq!(remaining2.len(), 1);
        assert_eq!(remaining2[0].ts, 300);

        std::fs::remove_dir_all(&layout.root).unwrap();
        assert!(!layout.root.exists());
    }

    #[test]
    fn absent_refs_serialize_as_dash() {
        let layout = tmp_layout("absent-refs");

        let id = ObjectId::of(b"work");
        record(
            &layout,
            "create branch",
            "main",
            "main",
            &[("work-1".to_string(), None, Some(id))],
        )
        .unwrap();

        let all = read_all(&layout).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].refs, vec![("work-1".to_string(), None, Some(id))]);

        std::fs::remove_dir_all(&layout.root).unwrap();
        assert!(!layout.root.exists());
    }
}
