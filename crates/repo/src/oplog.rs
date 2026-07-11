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
use crate::refs;
use crate::repo::Repo;
use crate::worktree;

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
    // `desc` must stay one line — strip both `\n` and `\r` so the
    // one-line-per-field grammar can never be desynchronized by a
    // hostile/careless description.
    let desc = rec.desc.replace(['\n', '\r'], " ");
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
///
/// If a prior crash left a torn partial block at the tail, appending after it
/// would leave the new record (and every future one) permanently invisible to
/// [`read_all`], which stops at the first malformed block — the log would
/// silently stop recording forever. So `record` first truncates the file back
/// to the end of the last well-formed block, then appends.
pub(crate) fn record(
    layout: &Layout,
    desc: &str,
    head_before: &str,
    head_after: &str,
    refs: &[(String, Option<ObjectId>, Option<ObjectId>)],
) -> Result<()> {
    // Defense in depth: the on-disk grammar is space-delimited and
    // one-line-per-field (see module docs), so a ref name containing
    // whitespace or control characters would write an unparseable block —
    // refuse before ever touching the file. `validate_branch_name` in
    // repo.rs is the primary guard; this catches any other caller.
    for (name, _, _) in refs {
        if name.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(Error::InvalidArgument(format!(
                "ref name {name:?} contains whitespace/control characters; would corrupt the oplog grammar"
            )));
        }
    }

    let path = layout.oplog_path();
    let contents = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(Error::Io(e)),
    };
    let (existing, consumed) = parse_contents(&contents);
    if consumed < contents.len() {
        // Torn/corrupt tail: drop the unparseable bytes so the append below
        // lands where read_all can see it.
        let f = OpenOptions::new().write(true).open(&path)?;
        f.set_len(consumed as u64)?;
        f.sync_all()?;
    }

    let seq = existing.last().map(|r| r.seq + 1).unwrap_or(1);
    let rec = OpRecord {
        seq,
        ts: crate::repo::unix_now(),
        desc: desc.to_string(),
        head_before: head_before.to_string(),
        head_after: head_after.to_string(),
        refs: refs.to_vec(),
    };
    let block = serialize(&rec);
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
        OpRecord {
            seq,
            ts,
            desc,
            head_before,
            head_after,
            refs,
        },
        i,
    ))
}

/// Parse the whole log body, returning every well-formed record in append
/// order plus the byte offset just past the last well-formed block. Bytes
/// beyond that offset are a torn/corrupt tail: [`read_all`] tolerates them
/// read-only; [`record`] truncates them before appending so the log never
/// silently stops recording.
fn parse_contents(contents: &str) -> (Vec<OpRecord>, usize) {
    // Split into lines while remembering where each line *ends* in the raw
    // byte stream (newline included), so a block index maps back to a
    // truncation offset.
    let mut lines: Vec<&str> = Vec::new();
    let mut line_ends: Vec<usize> = Vec::new();
    let mut pos = 0usize;
    for raw in contents.split_inclusive('\n') {
        pos += raw.len();
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let line = line.strip_suffix('\r').unwrap_or(line);
        lines.push(line);
        line_ends.push(pos);
    }

    let mut out = Vec::new();
    let mut i = 0;
    let mut consumed = 0;
    while i < lines.len() {
        match parse_block(&lines, i) {
            Some((rec, next)) => {
                out.push(rec);
                consumed = line_ends[next - 1];
                i = next;
            }
            None => break,
        }
    }
    (out, consumed)
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
    Ok(parse_contents(&contents).0)
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

/// What [`Repo::undo`] did: the undone record's description (for display)
/// plus any protected paths skipped — not decrypted — when the restore
/// re-materialized the working tree. Undo runs without an identity, so
/// protected files in the restored tree are removed from disk rather than
/// written as plaintext (same behavior and reporting as `sc switch` without
/// a key); `skipped` is empty when no re-materialize was needed.
#[derive(Debug)]
pub struct UndoOutcome {
    pub desc: String,
    pub skipped: Vec<String>,
}

impl Repo {
    /// Every well-formed operation-log record, oldest first (see the module
    /// docs for the on-disk grammar). Used by `sc oplog` and by callers that
    /// want to inspect history-editing state without going through `undo`.
    pub fn oplog(&self) -> Result<Vec<OpRecord>> {
        read_all(&self.layout)
    }

    /// Undo the most recently appended oplog record: restore every ref it
    /// touched (and HEAD, if it moved) to that record's before-state, and
    /// re-materialize the working tree when the restore actually changes what
    /// the (post-restore) current branch resolves to. The undo is itself
    /// logged as an inverse record, so undoing twice in a row redoes the
    /// original operation — `undo` is its own toggle.
    ///
    /// Refuses with:
    /// - [`Error::NothingToUndo`] if the log is empty.
    /// - [`Error::MergeInProgress`] while a merge is in progress (mirrors the
    ///   guard `merge`/`switch` already use).
    /// - [`Error::PickInProgress`] while a cherry-pick is in progress (same
    ///   guard, mirrored for pick state).
    /// - [`Error::RebaseInProgress`] while a rebase is stopped at a conflict
    ///   (same guard, mirrored for rebase state — undoing mid-rebase would
    ///   let `--continue` force-write over the undone ref move).
    /// - [`Error::InvalidArgument`] if a re-materialize is needed and the
    ///   working tree is dirty (would silently discard uncommitted work — the
    ///   same modified/deleted check `merge` and `switch` use).
    /// - [`Error::InvalidArgument`] if undoing would leave the current branch
    ///   unborn (restoring its ref to "absent"). This is a deliberate scope
    ///   cut: undoing the repo's very first commit has no working tree to
    ///   materialize back to, and silently deleting the ref file while
    ///   leaving stale tracked files on disk would be worse than refusing.
    ///   Undo an intermediate step instead of the first commit.
    ///
    /// Returns an [`UndoOutcome`]: the undone record's `desc` for CLI
    /// display, plus the protected paths skipped by the re-materialize (see
    /// the struct docs).
    pub fn undo(&self) -> Result<UndoOutcome> {
        let rec = last(&self.layout)?.ok_or(Error::NothingToUndo)?;

        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }

        // The branch that will be current once HEAD is restored.
        let restored_head = rec.head_before.clone();

        // Does the record's refs list move the tip of `restored_head`? If the
        // record doesn't mention it at all, its tip is untouched by this
        // record — read the ref's current (i.e. post-restore) value.
        let restored_head_entry = rec.refs.iter().find(|(name, _, _)| *name == restored_head);
        let (moves_current_tip, will_be_tip) = match restored_head_entry {
            Some((_, before, after)) => (before != after, *before),
            None => (false, refs::read_branch_tip(&self.layout, &restored_head)?),
        };
        let rematerialize = rec.head_before != rec.head_after || moves_current_tip;

        if rematerialize && will_be_tip.is_none() {
            return Err(Error::InvalidArgument(
                "cannot undo the initial commit (would unbear the branch)".into(),
            ));
        }

        if rematerialize {
            let dirty = self.status()?;
            if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
                return Err(Error::InvalidArgument(
                    "working tree has uncommitted changes; commit before undo".into(),
                ));
            }
        }

        // Capture the tree materialized right now, before any ref changes,
        // so re-materialize below knows what to remove.
        let old_root = if rematerialize {
            self.head_root()?
        } else {
            None
        };

        // Restore: ref writes first, inverse oplog record last (crash safety
        // — a crash between the two leaves the refs already-restored state
        // recoverable by re-running undo, never a torn write).
        for (name, before, _after) in &rec.refs {
            match before {
                Some(id) => refs::write_branch_tip(&self.layout, name, id)?,
                None => match std::fs::remove_file(self.layout.ref_path(name)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                },
            }
        }
        if rec.head_before != rec.head_after {
            refs::write_head(&self.layout, &rec.head_before)?;
        }

        let skipped = if rematerialize {
            // Guarded above: rematerialize implies will_be_tip is Some.
            let target_tip = will_be_tip.expect("checked non-unborn above");
            let (target_root, protection) = {
                let snap = self.snapshot(&target_tip)?;
                (snap.root, snap.protection)
            };
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            worktree::materialize(
                &self.layout,
                &mut store,
                target_root,
                old_root,
                &protection,
                None,
                &self.sparse_spec()?,
                None,
            )?
        } else {
            Vec::new()
        };

        // Log the inverse: swapped head, and every ref's before/after swapped.
        let inverse_refs: Vec<(String, Option<ObjectId>, Option<ObjectId>)> = rec
            .refs
            .iter()
            .map(|(name, before, after)| (name.clone(), *after, *before))
            .collect();
        record(
            &self.layout,
            &format!("undo of op {}: {}", rec.seq, rec.desc),
            &rec.head_after,
            &rec.head_before,
            &inverse_refs,
        )?;

        Ok(UndoOutcome {
            desc: rec.desc,
            skipped,
        })
    }
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

    /// A fresh persistent repo (via `Repo::init`) in its own temp dir, for
    /// exercising `undo` end-to-end. Returns the open handle plus its root so
    /// the caller can clean up (`Repo` holds the single-writer lock for its
    /// lifetime, so it must be dropped before `remove_dir_all`).
    fn setup_repo(tag: &str) -> (Repo, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("sc-undo-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repo = Repo::init(&root).unwrap();
        (repo, root)
    }

    fn teardown_repo(repo: Repo, root: &std::path::Path) {
        drop(repo);
        std::fs::remove_dir_all(root).unwrap();
        assert!(!root.exists());
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
    fn record_after_torn_tail_truncates_and_stays_visible() {
        let layout = tmp_layout("torn-tail");

        record(&layout, "good op", "main", "main", &[]).unwrap();

        // Simulate a crash mid-append: a genuinely truncated block — valid
        // prefix lines but no terminating `end`.
        let mut f = OpenOptions::new()
            .append(true)
            .open(layout.oplog_path())
            .unwrap();
        f.write_all(b"op 2\nts 123\ndesc half-written\nhead main main\n")
            .unwrap();
        drop(f);

        // The next record must not land behind the torn bytes.
        record(&layout, "after crash", "main", "main", &[]).unwrap();

        let all = read_all(&layout).unwrap();
        assert_eq!(
            all.len(),
            2,
            "new record must be visible past the torn tail"
        );
        assert_eq!(all[0].desc, "good op");
        assert_eq!(all[1].desc, "after crash");
        assert_eq!(all[1].seq, 2);

        // The torn bytes are physically gone, not just skipped.
        let raw = std::fs::read_to_string(layout.oplog_path()).unwrap();
        assert!(
            !raw.contains("half-written"),
            "torn tail should be truncated"
        );

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

    #[test]
    fn undo_commit_restores_ref_and_double_undo_redoes() {
        let (repo, root) = setup_repo("commit-undo");
        std::fs::write(root.join("a.txt"), "one\n").unwrap();
        let id1 = repo.commit("me", "commit one").unwrap();
        std::fs::write(root.join("a.txt"), "two\n").unwrap();
        let id2 = repo.commit("me", "commit two").unwrap();

        let outcome = repo.undo().unwrap();
        assert_eq!(outcome.desc, "commit: commit two");
        assert!(outcome.skipped.is_empty());
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "main").unwrap(),
            Some(id1)
        );
        // The object for the undone commit is still in the store — undo never
        // deletes objects, only moves refs.
        assert!(repo.store().lock().unwrap().get_snapshot(&id2).is_ok());

        // Double-undo redoes: the first undo logged its own inverse record,
        // and undoing *that* restores the tip to id2.
        let outcome2 = repo.undo().unwrap();
        assert!(
            outcome2.desc.starts_with("undo of op"),
            "got {:?}",
            outcome2.desc
        );
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "main").unwrap(),
            Some(id2)
        );

        teardown_repo(repo, &root);
    }

    #[test]
    fn undo_branch_create_deletes_the_ref_file() {
        let (repo, root) = setup_repo("branch-undo");
        std::fs::write(root.join("a.txt"), "base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        let feature_tip = refs::read_branch_tip(repo.layout(), "feature").unwrap();
        assert!(feature_tip.is_some());
        assert!(repo.layout().ref_path("feature").exists());

        let outcome = repo.undo().unwrap();
        assert_eq!(outcome.desc, "branch feature");
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "feature").unwrap(),
            None
        );
        assert!(!repo.layout().ref_path("feature").exists());

        // Redo direction (None → Some): undoing the inverse record recreates
        // the ref file pointing at its original tip.
        let redo = repo.undo().unwrap();
        assert!(redo.desc.starts_with("undo of op"), "got {:?}", redo.desc);
        assert!(repo.layout().ref_path("feature").exists());
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "feature").unwrap(),
            feature_tip
        );

        teardown_repo(repo, &root);
    }

    #[test]
    fn undo_switch_restores_head_and_working_tree() {
        let (repo, root) = setup_repo("switch-undo");
        std::fs::write(root.join("a.txt"), "main content\n").unwrap();
        repo.commit("me", "base on main").unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), "feature content\n").unwrap();
        repo.commit("me", "feature commit").unwrap();
        repo.switch("main").unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "main content\n"
        );

        let outcome = repo.undo().unwrap();
        assert_eq!(outcome.desc, "switch main");
        assert!(outcome.skipped.is_empty());
        assert_eq!(refs::current_branch(repo.layout()).unwrap(), "feature");
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "feature content\n"
        );

        teardown_repo(repo, &root);
    }

    #[test]
    fn undo_work_session_removes_all_harvested_branches() {
        let (repo, root) = setup_repo("work-undo");
        std::fs::write(root.join("a.txt"), "base\n").unwrap();
        repo.commit("me", "base").unwrap();

        let scratch = root.parent().unwrap().join("work-undo-scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let opts = crate::workspace::WorkOptions {
            agents: 2,
            base_name: "work".into(),
            cmd: vec![
                "sh".into(),
                "-c".into(),
                "echo \"$SC_WORKSPACE\" > out.txt".into(),
            ],
            author: "me".into(),
            message: None,
            identity: None,
            with_secrets: false,
            session_root: Some(scratch.join("session")),
        };
        let outcomes = repo.work(opts).unwrap();
        assert_eq!(outcomes.len(), 2);
        let work1_tip = refs::read_branch_tip(repo.layout(), "work-1").unwrap();
        let work2_tip = refs::read_branch_tip(repo.layout(), "work-2").unwrap();
        assert!(work1_tip.is_some());
        assert!(work2_tip.is_some());
        let main_before = refs::read_branch_tip(repo.layout(), "main").unwrap();

        let outcome = repo.undo().unwrap();
        assert!(
            outcome.desc.starts_with("work: 2 agents"),
            "got {:?}",
            outcome.desc
        );
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "work-1").unwrap(),
            None
        );
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "work-2").unwrap(),
            None
        );
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "main").unwrap(),
            main_before
        );
        assert_eq!(refs::current_branch(repo.layout()).unwrap(), "main");

        // Redo direction (None → Some): undoing the inverse record recreates
        // both harvested branch refs at their original tips.
        let redo = repo.undo().unwrap();
        assert!(redo.desc.starts_with("undo of op"), "got {:?}", redo.desc);
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "work-1").unwrap(),
            work1_tip
        );
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "work-2").unwrap(),
            work2_tip
        );
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "main").unwrap(),
            main_before
        );

        std::fs::remove_dir_all(&scratch).unwrap();
        teardown_repo(repo, &root);
    }

    #[test]
    fn undo_with_dirty_tree_refuses_when_rematerialize_needed() {
        let (repo, root) = setup_repo("dirty-undo");
        std::fs::write(root.join("a.txt"), "one\n").unwrap();
        repo.commit("me", "commit one").unwrap();
        std::fs::write(root.join("a.txt"), "two\n").unwrap();
        repo.commit("me", "commit two").unwrap();
        // Dirty the tracked file without committing.
        std::fs::write(root.join("a.txt"), "dirty\n").unwrap();

        let before_main = refs::read_branch_tip(repo.layout(), "main").unwrap();
        let err = repo.undo().unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "main").unwrap(),
            before_main
        );

        teardown_repo(repo, &root);
    }

    #[test]
    fn undo_merge_and_secret_add_round_trip() {
        let (repo, root) = setup_repo("merge-secret-undo");
        std::fs::write(root.join("shared.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nB\nc\n").unwrap();
        let pre_merge = repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nb\nC\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();
        let merge_id = repo.merge("feature", "me").unwrap();
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "main").unwrap(),
            Some(merge_id)
        );

        // Undo the merge: tip back to the pre-merge commit; the merge
        // snapshot stays reachable in the CAS.
        let outcome = repo.undo().unwrap();
        assert!(
            outcome.desc.starts_with("merge feature"),
            "got {:?}",
            outcome.desc
        );
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "main").unwrap(),
            Some(pre_merge)
        );
        assert!(repo.store().lock().unwrap().get_snapshot(&merge_id).is_ok());

        // Redo: undoing the inverse record restores the merge tip.
        let redo = repo.undo().unwrap();
        assert!(redo.desc.starts_with("undo of op"), "got {:?}", redo.desc);
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "main").unwrap(),
            Some(merge_id)
        );

        // secret add: moves the current branch's tip, same shape as a commit.
        let (_sk, pk) = scl_crypto::generate_keypair();
        let before_secret = refs::read_branch_tip(repo.layout(), "main").unwrap();
        repo.secret_add("DB_URL", b"v1", &[pk]).unwrap();
        assert_eq!(repo.secret_list().unwrap().len(), 1);

        let secret_undo = repo.undo().unwrap();
        assert_eq!(secret_undo.desc, "secret add DB_URL");
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "main").unwrap(),
            before_secret
        );
        assert!(repo.secret_list().unwrap().is_empty());

        teardown_repo(repo, &root);
    }

    #[test]
    fn undo_of_initial_commit_is_refused_to_keep_branch_born() {
        let (repo, root) = setup_repo("unbear");
        std::fs::write(root.join("a.txt"), "one\n").unwrap();
        let first = repo.commit("me", "first").unwrap();

        let err = repo.undo().unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        // Refused before any ref write: the branch is still born at the
        // first commit, not reverted to unborn.
        assert_eq!(
            refs::read_branch_tip(repo.layout(), "main").unwrap(),
            Some(first)
        );
        assert!(repo.layout().ref_path("main").exists());

        teardown_repo(repo, &root);
    }

    #[test]
    fn undo_across_protected_commit_reports_skipped_and_writes_no_plaintext() {
        let (repo, root) = setup_repo("protected-undo");
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("a.txt"), "base\n").unwrap();
        repo.commit("me", "base").unwrap();

        // Protect a prefix, then commit a file under it (encrypted at commit;
        // the plaintext stays on disk in the working tree, matching HEAD's
        // convergent ciphertext so status reads clean).
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/key.txt"), "hunter2\n").unwrap();
        repo.commit("me", "add protected").unwrap();

        // One more commit on top, so undo moves the tip back to a snapshot
        // that still contains the protected file.
        std::fs::write(root.join("a.txt"), "changed\n").unwrap();
        repo.commit("me", "second").unwrap();

        // Undo re-materializes with identity None: the protected path is
        // skipped (reported) and its on-disk plaintext is removed, never
        // rewritten — parity with `sc switch` without a key.
        let outcome = repo.undo().unwrap();
        assert_eq!(outcome.desc, "commit: second");
        assert_eq!(outcome.skipped, vec!["secret/key.txt".to_string()]);
        assert!(
            !root.join("secret/key.txt").exists(),
            "plaintext must not be written (or left) on disk without a key"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "base\n"
        );

        teardown_repo(repo, &root);
    }

    #[test]
    fn undo_on_empty_log_is_typed_error() {
        let (repo, root) = setup_repo("empty-log-undo");
        let err = repo.undo().unwrap_err();
        assert!(matches!(err, Error::NothingToUndo), "got {err:?}");
        teardown_repo(repo, &root);
    }

    #[test]
    fn record_refuses_ref_name_with_whitespace() {
        let layout = tmp_layout("bad-ref-name");

        let err = record(
            &layout,
            "commit with bad ref",
            "main",
            "main",
            &[("a b".to_string(), None, Some(ObjectId::of(b"x")))],
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");

        // Nothing was written: the log stays empty rather than gaining an
        // unparseable block.
        assert!(read_all(&layout).unwrap().is_empty());

        std::fs::remove_dir_all(&layout.root).unwrap();
        assert!(!layout.root.exists());
    }

    #[test]
    fn clone_does_not_copy_the_oplog() {
        let (repo, root) = setup_repo("clone-oplog-src");
        std::fs::write(root.join("a.txt"), "base\n").unwrap();
        repo.commit("me", "base").unwrap();
        assert!(!repo.oplog().unwrap().is_empty());

        let dst_root = root.parent().unwrap().join("clone-oplog-dst");
        let _ = std::fs::remove_dir_all(&dst_root);
        let dst = Repo::clone_to(&root, &dst_root).unwrap();

        // `clone_url` copies objects + refs selectively (see sync.rs), never
        // `.sc/oplog` — so the destination's log starts empty and undo there
        // is a typed NothingToUndo, not a reach into the source's history.
        assert!(dst.oplog().unwrap().is_empty());
        let err = dst.undo().unwrap_err();
        assert!(matches!(err, Error::NothingToUndo), "got {err:?}");

        drop(dst);
        std::fs::remove_dir_all(&dst_root).unwrap();
        teardown_repo(repo, &root);
    }
}
