//! Rebase-in-progress state under `.sc/`: `REBASE_STATE` (the stopped
//! rebase's fold progress — branch, original tip, target, accumulated tip,
//! the conflicted commit, and the remaining commits still to replay),
//! `REBASE_CONFLICTS` (newline-separated conflicted paths), and
//! `REBASE_DECIDED_ROOT` (the tree id of the stopped commit's decided
//! carried entries, mirroring P15 Task 6/7 — completion carries absent
//! protected files from it instead of re-arbitrating by parent order).
//! Written atomically; correctness relies on the single-writer repo lock.
//! Mirrors `pick_state.rs`: identity key material is NEVER stored here
//! (spec) — a resumed rebase re-derives decryption from a fresh
//! `--identity` flag, same as every other replay entry point.

use std::str::FromStr;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;

/// A stopped rebase's persisted progress. All ids are hex in the file;
/// identity key material is NEVER stored here (spec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebaseState {
    /// The branch being rebased.
    pub branch: String,
    /// The branch's tip before the rebase started — for `--abort` and the
    /// final oplog record.
    pub original_tip: ObjectId,
    /// The rebase target, display only (messages).
    pub target: String,
    /// Fold progress: the last successfully landed snapshot.
    pub acc_tip: ObjectId,
    /// The commit that stopped the rebase (conflicted).
    pub conflicted: ObjectId,
    /// Commits still to replay after `conflicted` is resolved, oldest first.
    pub remaining: Vec<ObjectId>,
    /// The total number of commits in the original replay range, for
    /// "k of n" status.
    pub total: usize,
    /// The author to record on the completion commit once the rebase folds
    /// through its last commit. NOT used as a default: the author passed to
    /// `sc rebase --continue` always wins (git-like — the resuming call's
    /// author, not the original rebase invocation's, is recorded on newly
    /// landed commits). Persisted for forward-compatibility / diagnostics
    /// only.
    pub author: String,
    /// True when `conflicted` has already been completed into `acc_tip` by a
    /// prior (possibly failed) `rebase_continue` call, and the fold over
    /// `remaining` is what's left to (re)do. This is what makes
    /// `rebase_continue` idempotent and error-recoverable (P19 review fix):
    /// if the resumed fold errors (e.g. `ProtectedMergeNeedsIdentity` on a
    /// later commit in `remaining`), state is NOT cleared, and a retry sees
    /// `resolved == true` and skips straight to the fold instead of
    /// re-completing `conflicted` (which would double-apply it). Defaults to
    /// `false` when absent from an on-disk file written before this field
    /// existed.
    pub resolved: bool,
    /// Cumulative count of commits landed (clean, empty-with-registry-change,
    /// or completed-from-conflict) across the WHOLE rebase so far, including
    /// every prior stop's segment — NOT just the segment since the last stop.
    /// Seeds `rebase_fold_and_finish`'s local counter on resume so the final
    /// oplog record's "N replayed" reflects the entire operation, matching
    /// the single-oplog-record collapse the rest of the resumable-rebase
    /// design already relies on. Backward parse defaults to 0, like
    /// `resolved`: a file written before this field existed predates any
    /// completed segment, so 0 is the correct reading.
    pub replayed: usize,
    /// Cumulative count of genuinely no-op commits (tree, own-rules delta,
    /// AND registry delta all empty) across the whole rebase so far. Same
    /// seeding/backward-parse discipline as `replayed`.
    pub skipped: usize,
}

fn state_path(layout: &Layout) -> std::path::PathBuf {
    layout.dot_sc.join("REBASE_STATE")
}
fn conflicts_path(layout: &Layout) -> std::path::PathBuf {
    layout.dot_sc.join("REBASE_CONFLICTS")
}
fn decided_root_path(layout: &Layout) -> std::path::PathBuf {
    layout.dot_sc.join("REBASE_DECIDED_ROOT")
}

/// True if a rebase is in progress.
pub fn in_progress(layout: &Layout) -> bool {
    state_path(layout).exists()
}

fn bad(msg: impl Into<String>) -> Error {
    Error::BadRef(format!("REBASE_STATE: {}", msg.into()))
}

fn parse_id(text: &str, field: &str) -> Result<ObjectId> {
    ObjectId::from_str(text).map_err(|_| bad(format!("bad id for {field}: {text}")))
}

fn parse_kv(line: &str, key: &str) -> Result<String> {
    let (k, v) = line
        .split_once('=')
        .ok_or_else(|| bad(format!("malformed line (expected \"{key}=...\"): {line}")))?;
    if k != key {
        return Err(bad(format!("expected field \"{key}\", got \"{k}\"")));
    }
    Ok(v.to_string())
}

/// Serialize a `RebaseState` to `REBASE_STATE`'s on-disk text format: a
/// `k=v` header block (one field per line, in a fixed order), followed by
/// the remaining commit ids one per line.
fn serialize(st: &RebaseState) -> String {
    let mut out = String::new();
    out.push_str(&format!("branch={}\n", st.branch));
    out.push_str(&format!("original_tip={}\n", st.original_tip.to_hex()));
    out.push_str(&format!("target={}\n", st.target));
    out.push_str(&format!("acc_tip={}\n", st.acc_tip.to_hex()));
    out.push_str(&format!("conflicted={}\n", st.conflicted.to_hex()));
    out.push_str(&format!("total={}\n", st.total));
    out.push_str(&format!("author={}\n", st.author));
    out.push_str(&format!("resolved={}\n", st.resolved));
    out.push_str(&format!("replayed={}\n", st.replayed));
    out.push_str(&format!("skipped={}\n", st.skipped));
    for id in &st.remaining {
        out.push_str(&format!("{}\n", id.to_hex()));
    }
    out
}

/// Parse `REBASE_STATE`'s on-disk text format. Strict: any malformed or
/// missing field is `Error::BadRef` rather than a silent default.
fn deserialize(text: &str) -> Result<RebaseState> {
    let mut lines = text.lines().peekable();
    let branch = parse_kv(lines.next().ok_or_else(|| bad("missing branch"))?, "branch")?;
    let original_tip = parse_id(
        &parse_kv(lines.next().ok_or_else(|| bad("missing original_tip"))?, "original_tip")?,
        "original_tip",
    )?;
    let target = parse_kv(lines.next().ok_or_else(|| bad("missing target"))?, "target")?;
    let acc_tip = parse_id(
        &parse_kv(lines.next().ok_or_else(|| bad("missing acc_tip"))?, "acc_tip")?,
        "acc_tip",
    )?;
    let conflicted = parse_id(
        &parse_kv(lines.next().ok_or_else(|| bad("missing conflicted"))?, "conflicted")?,
        "conflicted",
    )?;
    let total_text = parse_kv(lines.next().ok_or_else(|| bad("missing total"))?, "total")?;
    let total: usize = total_text.parse().map_err(|_| bad(format!("bad total: {total_text}")))?;
    let author = parse_kv(lines.next().ok_or_else(|| bad("missing author"))?, "author")?;
    // `resolved=` is optional on parse (added after the initial P19 shape) —
    // a file written before this field existed simply defaults to `false`,
    // which is the correct reading: nothing has completed yet beyond what
    // `acc_tip` already reflects.
    let resolved = match lines.peek() {
        Some(line) if line.starts_with("resolved=") => {
            let text = parse_kv(lines.next().unwrap(), "resolved")?;
            text.parse::<bool>().map_err(|_| bad(format!("bad resolved: {text}")))?
        }
        _ => false,
    };
    // `replayed=`/`skipped=` are optional on parse for the same reason as
    // `resolved=` — a file written before P21 has no completed segment to
    // count yet, so 0 is the correct default.
    let replayed = match lines.peek() {
        Some(line) if line.starts_with("replayed=") => {
            let text = parse_kv(lines.next().unwrap(), "replayed")?;
            text.parse::<usize>().map_err(|_| bad(format!("bad replayed: {text}")))?
        }
        _ => 0,
    };
    let skipped = match lines.peek() {
        Some(line) if line.starts_with("skipped=") => {
            let text = parse_kv(lines.next().unwrap(), "skipped")?;
            text.parse::<usize>().map_err(|_| bad(format!("bad skipped: {text}")))?
        }
        _ => 0,
    };
    let mut remaining = Vec::new();
    for line in lines {
        remaining.push(parse_id(line, "remaining")?);
    }
    Ok(RebaseState {
        branch,
        original_tip,
        target,
        acc_tip,
        conflicted,
        remaining,
        total,
        author,
        resolved,
        replayed,
        skipped,
    })
}

/// Write the stopped rebase's state. `REBASE_STATE` is written LAST — it is
/// the `in_progress` signal, so a crash mid-write leaves no half-announced
/// rebase (same discipline as `pick_state::write`).
pub fn write(layout: &Layout, st: &RebaseState) -> Result<()> {
    atomic_write(&state_path(layout), serialize(st).as_bytes())?;
    Ok(())
}

/// Read the stopped rebase's state, if any.
pub fn read(layout: &Layout) -> Result<Option<RebaseState>> {
    match std::fs::read_to_string(state_path(layout)) {
        Ok(text) => deserialize(&text).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Clear all rebase state (after a successful `--continue` completion or
/// `--abort`).
pub fn clear(layout: &Layout) -> Result<()> {
    remove_if_exists(&state_path(layout))?;
    remove_if_exists(&conflicts_path(layout))?;
    remove_if_exists(&decided_root_path(layout))?;
    Ok(())
}

/// The conflicted paths recorded for the in-progress rebase's stopped commit.
pub fn read_conflicts(layout: &Layout) -> Result<Vec<String>> {
    match std::fs::read_to_string(conflicts_path(layout)) {
        Ok(text) => Ok(text.lines().map(|l| l.to_string()).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// Record the conflicted paths for the in-progress rebase's stopped commit.
pub fn write_conflicts(layout: &Layout, paths: &[String]) -> Result<()> {
    atomic_write(&conflicts_path(layout), (paths.join("\n") + "\n").as_bytes())
}

/// The decided-carried tree of the in-progress rebase's stopped commit, if
/// recorded. Gated on `REBASE_STATE`'s presence, mirroring the merge/pick
/// decided-root crash discipline: the conflict path writes the decided root
/// BEFORE `REBASE_STATE` (the `in_progress` signal), so a crash in that
/// window can leave a decided-root file with no matching state. Such
/// residue must be inert — reads None once `REBASE_STATE` is gone, even if
/// the file itself was left behind.
pub fn read_decided_root(layout: &Layout) -> Result<Option<ObjectId>> {
    if !in_progress(layout) {
        return Ok(None);
    }
    match std::fs::read_to_string(decided_root_path(layout)) {
        Ok(text) => ObjectId::from_str(text.trim())
            .map(Some)
            .map_err(|_| bad(format!("REBASE_DECIDED_ROOT has bad id: {}", text.trim()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Record the tree id holding the stopped rebase commit's decided carried
/// entries, which completion uses to carry absent protected files without
/// re-reading a stale tip.
pub fn write_decided_root(layout: &Layout, tree: ObjectId) -> Result<()> {
    atomic_write(&decided_root_path(layout), format!("{}\n", tree.to_hex()).as_bytes())
}

/// Remove a file, treating "already absent" as success but propagating any
/// other IO error rather than swallowing it.
fn remove_if_exists(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    // Build the tmp path as "<file_name>.tmp" so we don't clobber a sibling
    // that differs only by extension (e.g. REBASE_STATE vs REBASE_STATE.tmp,
    // not turning "foo.bar" into "foo.tmp").
    let name = path
        .file_name()
        .ok_or_else(|| Error::InvalidArgument(format!("path has no file name: {}", path.display())))?
        .to_string_lossy()
        .into_owned();
    let tmp = path.with_file_name(format!("{name}.tmp"));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_layout(tag: &str) -> Layout {
        let root =
            std::env::temp_dir().join(format!("scl-rebasestate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        layout
    }

    fn sample(tag: &str) -> RebaseState {
        RebaseState {
            branch: "feature".into(),
            original_tip: ObjectId::of(format!("orig-{tag}").as_bytes()),
            target: "main".into(),
            acc_tip: ObjectId::of(format!("acc-{tag}").as_bytes()),
            conflicted: ObjectId::of(format!("conflicted-{tag}").as_bytes()),
            remaining: vec![
                ObjectId::of(format!("rem1-{tag}").as_bytes()),
                ObjectId::of(format!("rem2-{tag}").as_bytes()),
            ],
            total: 4,
            author: "me".into(),
            resolved: false,
            replayed: 0,
            skipped: 0,
        }
    }

    #[test]
    fn write_read_clear_roundtrip() {
        let layout = tmp_layout("rt");
        assert!(!in_progress(&layout));
        let st = sample("rt");
        write(&layout, &st).unwrap();
        assert!(in_progress(&layout));
        assert_eq!(read(&layout).unwrap(), Some(st.clone()));
        clear(&layout).unwrap();
        assert!(!in_progress(&layout));
        assert_eq!(read(&layout).unwrap(), None);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn in_progress_truthiness() {
        let layout = tmp_layout("truthy");
        assert!(!in_progress(&layout));
        write(&layout, &sample("truthy")).unwrap();
        assert!(in_progress(&layout));
        clear(&layout).unwrap();
        assert!(!in_progress(&layout));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn malformed_state_file_is_bad_ref() {
        let layout = tmp_layout("malformed");
        std::fs::write(state_path(&layout), b"not a valid rebase state\n").unwrap();
        let err = read(&layout).unwrap_err();
        assert!(matches!(err, Error::BadRef(_)), "got {err:?}");
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn malformed_state_bad_total_is_bad_ref() {
        let layout = tmp_layout("badtotal");
        write(&layout, &sample("badtotal")).unwrap();
        // Corrupt the "total=" line directly rather than reconstructing the
        // whole serialized form, so this test tracks the format loosely.
        let raw = std::fs::read_to_string(state_path(&layout)).unwrap();
        let patched = raw
            .lines()
            .map(|l| if l.starts_with("total=") { "total=not-a-number" } else { l })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(state_path(&layout), patched).unwrap();
        let err = read(&layout).unwrap_err();
        assert!(matches!(err, Error::BadRef(_)), "got {err:?}");
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn decided_root_gated_on_state_presence() {
        let layout = tmp_layout("gated");
        assert_eq!(read_decided_root(&layout).unwrap(), None, "no state yet: reads None");
        let st = sample("gated");
        write(&layout, &st).unwrap();
        let decided = ObjectId::of(b"decided-tree");
        write_decided_root(&layout, decided).unwrap();
        assert_eq!(read_decided_root(&layout).unwrap(), Some(decided));
        // Clear the state but leave REBASE_DECIDED_ROOT behind, simulating
        // the crash-residue case: the decided root must read as absent once
        // REBASE_STATE (the in_progress signal) is gone, even though the
        // file itself is still on disk.
        remove_if_exists(&state_path(&layout)).unwrap();
        assert!(decided_root_path(&layout).exists(), "test setup: residue must remain");
        assert_eq!(
            read_decided_root(&layout).unwrap(),
            None,
            "decided root must be inert once REBASE_STATE is gone"
        );
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn resolved_roundtrip() {
        let layout = tmp_layout("resolved");
        let mut st = sample("resolved");
        st.resolved = true;
        write(&layout, &st).unwrap();
        assert_eq!(read(&layout).unwrap(), Some(st));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn resolved_defaults_false_when_absent_from_file() {
        // Simulates a REBASE_STATE written before the `resolved` field
        // existed: no "resolved=" line at all, remaining ids immediately
        // follow "author=".
        let layout = tmp_layout("resolved-absent");
        let st = sample("resolved-absent");
        let mut text = String::new();
        text.push_str(&format!("branch={}\n", st.branch));
        text.push_str(&format!("original_tip={}\n", st.original_tip.to_hex()));
        text.push_str(&format!("target={}\n", st.target));
        text.push_str(&format!("acc_tip={}\n", st.acc_tip.to_hex()));
        text.push_str(&format!("conflicted={}\n", st.conflicted.to_hex()));
        text.push_str(&format!("total={}\n", st.total));
        text.push_str(&format!("author={}\n", st.author));
        for id in &st.remaining {
            text.push_str(&format!("{}\n", id.to_hex()));
        }
        std::fs::write(state_path(&layout), text).unwrap();
        let read_back = read(&layout).unwrap().unwrap();
        assert!(!read_back.resolved, "must default to false when the field is absent");
        assert_eq!(read_back.remaining, st.remaining, "remaining ids must still parse correctly");
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn counters_roundtrip() {
        let layout = tmp_layout("counters");
        let mut st = sample("counters");
        st.replayed = 3;
        st.skipped = 2;
        write(&layout, &st).unwrap();
        assert_eq!(read(&layout).unwrap(), Some(st));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn counters_default_zero_when_absent_from_file() {
        // Simulates a REBASE_STATE written before the `replayed`/`skipped`
        // fields existed (P19-era file with only `resolved=`): no counter
        // lines at all, remaining ids immediately follow `resolved=`.
        let layout = tmp_layout("counters-absent");
        let st = sample("counters-absent");
        let mut text = String::new();
        text.push_str(&format!("branch={}\n", st.branch));
        text.push_str(&format!("original_tip={}\n", st.original_tip.to_hex()));
        text.push_str(&format!("target={}\n", st.target));
        text.push_str(&format!("acc_tip={}\n", st.acc_tip.to_hex()));
        text.push_str(&format!("conflicted={}\n", st.conflicted.to_hex()));
        text.push_str(&format!("total={}\n", st.total));
        text.push_str(&format!("author={}\n", st.author));
        text.push_str(&format!("resolved={}\n", st.resolved));
        for id in &st.remaining {
            text.push_str(&format!("{}\n", id.to_hex()));
        }
        std::fs::write(state_path(&layout), text).unwrap();
        let read_back = read(&layout).unwrap().unwrap();
        assert_eq!(read_back.replayed, 0, "must default to 0 when the field is absent");
        assert_eq!(read_back.skipped, 0, "must default to 0 when the field is absent");
        assert_eq!(read_back.remaining, st.remaining, "remaining ids must still parse correctly");
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn conflicts_roundtrip() {
        let layout = tmp_layout("conflicts");
        assert_eq!(read_conflicts(&layout).unwrap(), Vec::<String>::new());
        write_conflicts(&layout, &["a.txt".into(), "b.txt".into()]).unwrap();
        assert_eq!(read_conflicts(&layout).unwrap(), vec!["a.txt", "b.txt"]);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
