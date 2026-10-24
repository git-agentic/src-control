//! Pull requests: storage, the git computations behind a PR object, and the retention refs.
//!
//! A PR is a row naming a head and a base branch of one repository (forks are a non-goal). Its
//! `head.sha` is the live tip of the head branch; when that branch is gone it is the head the
//! server retained in `refs/forge/pull/<n>/head`, and a PR whose head branch is deleted is closed
//! (recorded, both Gitea versions). A merged PR's head and stats are frozen at merge.
//!
//! The retention ref is written only by the server, always under the repository's write gate
//! (`lifecycle`'s lock order), or by the `pre-receive` hook for a push that deletes the head
//! branch of an open PR. [`sync_locked`] makes refs and rows agree after anything that can move a
//! branch (a push, a contents write, a branch delete, startup); reads never write.

use crate::gitobj;
use crate::gitproc::{Git, GitError, Spec};
use crate::lifecycle::{Lifecycle, WriteRun};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// Retention ref of PR `n`.
pub fn retention_ref(n: i64) -> String {
    format!("refs/forge/pull/{n}/head")
}

/// The ref that keeps the merge commit of merged pull request `n` alive after the base moves on
/// (the landing marker is retired once the merge is final).
pub fn merge_ref(n: i64) -> String {
    format!("refs/forge/pull/{n}/merge")
}

/// A stored pull request.
#[derive(Clone, Debug)]
pub struct Pull {
    pub id: i64,
    pub repo_id: i64,
    pub number: i64,
    pub head_ref: String,
    pub base_ref: String,
    pub base_sha: String,
    pub head_sha: String,
    pub title: String,
    pub body: String,
    /// `open`, `closed` or `merged`.
    pub state: String,
    pub creator_id: i64,
    pub created: i64,
    pub updated: i64,
    pub closed: Option<i64>,
    pub final_head: Option<String>,
    pub merge_commit: Option<String>,
    pub merged: Option<i64>,
    pub merged_by: Option<i64>,
    pub merge_base: Option<String>,
    pub changed_files: Option<i64>,
    pub additions: Option<i64>,
    pub deletions: Option<i64>,
    /// Open with a head branch that no longer exists (reopened after its branch was deleted).
    pub head_gone: bool,
}

const COLS: &str =
    "id, repo_id, number, head_ref, base_ref, base_sha, head_sha, title, body, state, \
    creator_id, created_unix, updated_unix, closed_unix, final_head_sha, merge_commit_sha, \
    merged_unix, merged_by, merge_base, changed_files, additions, deletions, head_gone";

fn row(r: &rusqlite::Row) -> rusqlite::Result<Pull> {
    Ok(Pull {
        id: r.get(0)?,
        repo_id: r.get(1)?,
        number: r.get(2)?,
        head_ref: r.get(3)?,
        base_ref: r.get(4)?,
        base_sha: r.get(5)?,
        head_sha: r.get(6)?,
        title: r.get(7)?,
        body: r.get(8)?,
        state: r.get(9)?,
        creator_id: r.get(10)?,
        created: r.get(11)?,
        updated: r.get(12)?,
        closed: r.get(13)?,
        final_head: r.get(14)?,
        merge_commit: r.get(15)?,
        merged: r.get(16)?,
        merged_by: r.get(17)?,
        merge_base: r.get(18)?,
        changed_files: r.get(19)?,
        additions: r.get(20)?,
        deletions: r.get(21)?,
        head_gone: r.get::<_, i64>(22)? != 0,
    })
}

/// PR `number` of the repository.
pub fn find(conn: &Connection, repo_id: i64, number: i64) -> rusqlite::Result<Option<Pull>> {
    conn.query_row(
        &format!("SELECT {COLS} FROM pulls WHERE repo_id = ?1 AND number = ?2"),
        params![repo_id, number],
        row,
    )
    .optional()
}

/// The open PR with exactly these targets, if any.
pub fn find_open(
    conn: &Connection,
    repo_id: i64,
    head: &str,
    base: &str,
) -> rusqlite::Result<Option<Pull>> {
    conn.query_row(
        &format!(
            "SELECT {COLS} FROM pulls WHERE repo_id = ?1 AND head_ref = ?2 AND base_ref = ?3 AND state = 'open'"
        ),
        params![repo_id, head, base],
        row,
    )
    .optional()
}

/// Every open PR of the repository.
pub fn open_pulls(conn: &Connection, repo_id: i64) -> rusqlite::Result<Vec<Pull>> {
    let mut st = conn.prepare(&format!(
        "SELECT {COLS} FROM pulls WHERE repo_id = ?1 AND state = 'open' ORDER BY number"
    ))?;
    let rows = st.query_map([repo_id], row)?.collect();
    rows
}

/// How a listing is ordered (`sort=`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sort {
    Newest,
    Oldest,
    RecentUpdate,
}

/// PRs of the repository in `states`, a page of them, and the total.
pub fn list(
    conn: &Connection,
    repo_id: i64,
    states: &[&str],
    sort: Sort,
    offset: i64,
    limit: i64,
) -> rusqlite::Result<(Vec<Pull>, i64)> {
    let marks = vec!["?"; states.len()].join(",");
    let order = match sort {
        Sort::Newest => "number DESC",
        Sort::Oldest => "number ASC",
        Sort::RecentUpdate => "updated_unix DESC, number DESC",
    };
    let mut args: Vec<rusqlite::types::Value> = vec![repo_id.into()];
    args.extend(states.iter().map(|s| (*s).to_string().into()));
    let total = conn.query_row(
        &format!("SELECT COUNT(*) FROM pulls WHERE repo_id = ? AND state IN ({marks})"),
        rusqlite::params_from_iter(args.iter()),
        |r| r.get(0),
    )?;
    args.push(limit.into());
    args.push(offset.into());
    let mut st = conn.prepare(&format!(
        "SELECT {COLS} FROM pulls WHERE repo_id = ? AND state IN ({marks}) ORDER BY {order} LIMIT ? OFFSET ?"
    ))?;
    let rows = st
        .query_map(rusqlite::params_from_iter(args.iter()), row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((rows, total))
}

/// The number the next PR of the repository gets.
pub fn next_number(conn: &Connection, repo_id: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COALESCE(MAX(number), 0) + 1 FROM pulls WHERE repo_id = ?1",
        [repo_id],
        |r| r.get(0),
    )
}

/// Insert a PR with the next number of the repository (PRs and, one day, issues share it).
pub fn insert(
    conn: &Connection,
    repo_id: i64,
    head: &str,
    base: &str,
    base_sha: &str,
    head_sha: &str,
    title: &str,
    body: &str,
    creator: i64,
    now: i64,
) -> rusqlite::Result<Pull> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let number: i64 = tx.query_row(
        "SELECT COALESCE(MAX(number), 0) + 1 FROM pulls WHERE repo_id = ?1",
        [repo_id],
        |r| r.get(0),
    )?;
    tx.execute(
        "INSERT INTO pulls (repo_id, number, head_ref, base_ref, base_sha, head_sha, title, body, \
         state, creator_id, created_unix, updated_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'open', ?9, ?10, ?10)",
        params![repo_id, number, head, base, base_sha, head_sha, title, body, creator, now],
    )?;
    let p = tx.query_row(
        &format!("SELECT {COLS} FROM pulls WHERE repo_id = ?1 AND number = ?2"),
        params![repo_id, number],
        row,
    )?;
    tx.commit()?;
    Ok(p)
}

/// Write back the editable and lifecycle columns of `p`.
pub fn save(conn: &Connection, p: &Pull) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE pulls SET base_ref = ?1, base_sha = ?2, head_sha = ?3, title = ?4, body = ?5, state = ?6, \
         updated_unix = ?7, closed_unix = ?8, final_head_sha = ?9, head_gone = ?10 WHERE id = ?11",
        params![
            p.base_ref,
            p.base_sha,
            p.head_sha,
            p.title,
            p.body,
            p.state,
            p.updated,
            p.closed,
            p.final_head,
            p.head_gone,
            p.id
        ],
    )?;
    Ok(())
}

/// Comments on the PR (the issue-comment count the PR object reports).
pub fn comment_count(conn: &Connection, repo_id: i64, number: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM issue_comments WHERE repo_id = ?1 AND number = ?2",
        params![repo_id, number],
        |r| r.get(0),
    )
}

// ---- git: what a PR is made of ----

/// What `base...head` is: cached by the two object ids, which are immutable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compute {
    pub mergeable: bool,
    pub merge_base: Option<String>,
    pub changed_files: i64,
    pub additions: i64,
    pub deletions: i64,
}

fn cached(
    conn: &Connection,
    repo_id: i64,
    base: &str,
    head: &str,
) -> rusqlite::Result<Option<Compute>> {
    conn.query_row(
        "SELECT mergeable, merge_base, changed_files, additions, deletions FROM mergeability_cache \
         WHERE repo_id = ?1 AND base_sha = ?2 AND head_sha = ?3",
        params![repo_id, base, head],
        |r| {
            Ok(Compute {
                mergeable: r.get::<_, i64>(0)? != 0,
                merge_base: r.get::<_, Option<String>>(1)?.filter(|s| !s.is_empty()),
                changed_files: r.get(2)?,
                additions: r.get(3)?,
                deletions: r.get(4)?,
            })
        },
    )
    .optional()
}

/// The merge base of two commits, or `None` for unrelated histories.
pub fn merge_base(git: &Git, dir: &Path, a: &str, b: &str) -> Result<Option<String>, GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &["merge-base", "--end-of-options", a, b],
        ..Default::default()
    })?;
    match out.status.code() {
        Some(0) => Ok(Some(out.text())),
        Some(1) => Ok(None),
        _ => Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        )),
    }
}

/// Does merging `head` into `base` conflict? `merge-tree --write-tree`: 0 clean, 1 conflicts,
/// anything else is an error (never inferred from output).
pub fn merges_cleanly(git: &Git, dir: &Path, base: &str, head: &str) -> Result<bool, GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &[
            "merge-tree",
            "--write-tree",
            "--no-messages",
            "--end-of-options",
            base,
            head,
        ],
        ..Default::default()
    })?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        )),
    }
}

/// Compute (or read from the cache) the facts of `base...head`.
pub fn compute(
    conn: &Connection,
    git: &Git,
    dir: &Path,
    repo_id: i64,
    base: &str,
    head: &str,
) -> Result<Compute, ComputeError> {
    if let Some(c) = cached(conn, repo_id, base, head)? {
        return Ok(c);
    }
    let mb = merge_base(git, dir, base, head)?;
    // Unrelated histories: the changes are counted against the base tip (recorded T#0).
    let (files, stats) = gitobj::changes(git, dir, Some(mb.as_deref().unwrap_or(base)), head)?;
    // Unrelated histories cannot merge; `merge-tree` would die on them.
    let mergeable = mb.is_some() && merges_cleanly(git, dir, base, head)?;
    let c = Compute {
        mergeable,
        merge_base: mb,
        changed_files: files.len() as i64,
        additions: stats.additions as i64,
        deletions: stats.deletions as i64,
    };
    conn.execute(
        "INSERT OR REPLACE INTO mergeability_cache (repo_id, base_sha, head_sha, mergeable, merge_base, \
         changed_files, additions, deletions) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            repo_id,
            base,
            head,
            c.mergeable,
            c.merge_base.clone().unwrap_or_default(),
            c.changed_files,
            c.additions,
            c.deletions
        ],
    )?;
    // Bounded per repository: obsolete (base, head) pairs of branches that moved on go oldest first.
    conn.execute(
        "DELETE FROM mergeability_cache WHERE repo_id = ?1 AND rowid NOT IN \
         (SELECT rowid FROM mergeability_cache WHERE repo_id = ?1 ORDER BY rowid DESC LIMIT ?2)",
        params![repo_id, CACHE_PER_REPO],
    )?;
    Ok(c)
}

/// Mergeability rows kept per repository.
const CACHE_PER_REPO: i64 = 2_000;

/// Why [`compute`] failed.
#[derive(Debug, thiserror::Error)]
pub enum ComputeError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Git(#[from] GitError),
}

// ---- retention refs ----

/// `(full ref name, object id)` of every ref under `prefix`.
pub fn refs_under(
    git: &Git,
    dir: &Path,
    prefix: &str,
) -> Result<HashMap<String, String>, GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &["for-each-ref", "--format=%(refname) %(objectname)", prefix],
        ..Default::default()
    })?;
    if !out.ok() {
        return Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(n, o)| (n.to_string(), o.to_string()))
        .collect())
}

/// Point PR `n`'s retention ref at `oid` (a commit that exists), whatever it holds now. For the
/// authoritative writers: PR creation, close, and the record of a head that is about to be deleted.
pub fn retain(git: &Git, dir: &Path, n: i64, oid: &str) -> Result<(), GitError> {
    retain_at(git, dir, &retention_ref(n), oid)
}

/// Point `r` (one of the `refs/forge/pull/<n>/…` refs) at `oid`, whatever it holds now.
pub fn retain_at(git: &Git, dir: &Path, r: &str, oid: &str) -> Result<(), GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &["update-ref", r, oid],
        ..Default::default()
    })?;
    if out.ok() {
        Ok(())
    } else {
        Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

/// Move PR `n`'s retention ref from `expected` (`None` = it must not exist) to `oid`, and only
/// then. `Ok(false)` means someone else changed it in the meantime (a push's hook records the tip
/// of a deleted head without the write gate): the caller leaves it alone, because a newer value
/// must never be overwritten by a stale snapshot.
pub fn retain_cas(
    git: &Git,
    dir: &Path,
    n: i64,
    oid: &str,
    expected: Option<&str>,
) -> Result<bool, GitError> {
    let r = retention_ref(n);
    let zero = "0".repeat(oid.len());
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &["update-ref", &r, oid, expected.unwrap_or(&zero)],
        ..Default::default()
    })?;
    Ok(out.ok())
}

/// Retain `oid` for every open PR whose head branch is `branch` (called with the exclusive
/// lifecycle lock held, just before the branch is deleted).
pub fn retain_for_branch(
    conn: &Connection,
    git: &Git,
    dir: &Path,
    repo_id: i64,
    branch: &str,
    oid: &str,
) -> Result<(), ComputeError> {
    for p in open_pulls(conn, repo_id)? {
        if p.head_ref == branch {
            retain(git, dir, p.number, oid)?;
        }
    }
    Ok(())
}

/// The tip of branch `name` in a `refs/heads` listing. Exact: on a case-sensitive filesystem
/// `feature` and `Feature` are two branches. (On a case-insensitive development filesystem a PR
/// opened with a differently cased name reads as vanished; production is Linux.)
fn head_tip(heads: &HashMap<String, String>, name: &str) -> Option<String> {
    heads.get(&format!("refs/heads/{name}")).cloned()
}

/// Does an open PR of the repository have a head branch that is gone without the PR knowing
/// (not reopened that way)? Reads use it to converge after a push that deleted a head, whose
/// own sync may not have run yet.
pub fn has_vanished_head(conn: &Connection, git: &Git, dir: &Path, repo_id: i64) -> bool {
    let Ok(open) = open_pulls(conn, repo_id) else {
        return false;
    };
    let watched: Vec<&Pull> = open.iter().filter(|p| !p.head_gone).collect();
    if watched.is_empty() {
        return false;
    }
    match refs_under(git, dir, "refs/heads") {
        Ok(heads) => watched
            .iter()
            .any(|p| head_tip(&heads, &p.head_ref).is_none()),
        Err(_) => false,
    }
}

/// [`sync_locked`] for one PR; `true` when it closed it.
fn sync_one(
    conn: &Connection,
    git: &Git,
    dir: &Path,
    mut p: Pull,
    kept: &HashMap<String, String>,
    heads: &HashMap<String, String>,
    now: i64,
) -> Result<bool, ComputeError> {
    let tip = head_tip(heads, &p.head_ref);
    let have = kept.get(&retention_ref(p.number)).cloned();
    match tip {
        Some(t) => {
            if have.as_deref() != Some(t.as_str()) {
                retain_cas(git, dir, p.number, &t, have.as_deref())?;
            }
            if p.head_sha != t || p.head_gone {
                p.head_sha = t;
                p.head_gone = false;
                save(conn, &p)?;
            }
            Ok(false)
        }
        // Reopened without its branch: stays open on the retained head.
        None if p.head_gone => Ok(false),
        None => {
            // The branch is gone, so whoever deleted it has recorded its tip: read that now.
            let head = refs_under(git, dir, &retention_ref(p.number))?
                .remove(&retention_ref(p.number))
                .unwrap_or_else(|| p.head_sha.clone());
            retain(git, dir, p.number, &head)?;
            p.head_sha = head.clone();
            p.final_head = Some(head);
            p.state = "closed".into();
            p.closed = Some(now);
            p.updated = now;
            save(conn, &p)?;
            Ok(true)
        }
    }
}

/// Bring refs and rows into agreement, with the write gate held: an open PR's retention ref
/// follows its head branch; a PR whose head branch is gone keeps the retained head and is
/// closed. Returns how many PRs it closed.
pub fn sync_locked(
    conn: &Connection,
    git: &Git,
    dir: &Path,
    repo_id: i64,
    now: i64,
) -> Result<usize, ComputeError> {
    // A merge that landed is finalized before any pull request is closed or moved on; one that
    // cannot be settled yet (a git writer still holds its base) blocks the sync.
    crate::merges::recover_locked(conn, git, dir, repo_id)?;
    if crate::merges::has_pending(conn, repo_id) {
        return Ok(0);
    }
    let open = open_pulls(conn, repo_id)?;
    if open.is_empty() {
        return Ok(0);
    }
    // The retention refs are read before the branches: a head deleted by a push in between has
    // had its tip recorded by the hook already, and every write below is a compare-and-swap on
    // what was read, so a stale snapshot can never overwrite a newer retained head.
    let kept = refs_under(git, dir, "refs/forge/pull")?;
    let heads = refs_under(git, dir, "refs/heads")?;
    let mut closed = 0;
    for p in open {
        let number = p.number;
        // One PR that cannot be synced (a git failure on its ref) must not keep the others from it.
        match sync_one(conn, git, dir, p, &kept, &heads, now) {
            Ok(c) => closed += usize::from(c),
            Err(e) => eprintln!("sc-forge: could not sync pull request {number}: {e}"),
        }
    }
    Ok(closed)
}

/// The startup repair of one repository: [`sync_locked`], retention refs of closed and merged
/// PRs recreated from their stored final head, and `refs/forge/pull/*` refs with no PR row
/// removed (only that namespace's `head` refs).
pub fn reconcile_repo(
    conn: &Connection,
    git: &Git,
    dir: &Path,
    repo_id: i64,
    now: i64,
) -> Result<(), ComputeError> {
    // A merge a crash interrupted is settled first: its receipt decides, then stray receipts go.
    crate::merges::recover_locked(conn, git, dir, repo_id)?;
    crate::merges::drop_stale_receipts(conn, git, dir, repo_id)?;
    sync_locked(conn, git, dir, repo_id, now)?;
    let kept = refs_under(git, dir, "refs/forge/pull")?;
    let mut st = conn.prepare(
        "SELECT number, state, final_head_sha, merge_commit_sha FROM pulls WHERE repo_id = ?1",
    )?;
    let rows: Vec<(i64, String, Option<String>, Option<String>)> = st
        .query_map([repo_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let known: HashMap<i64, (String, Option<String>)> = rows
        .iter()
        .map(|(n, s, h, _)| (*n, (s.clone(), h.clone())))
        .collect();
    // A merged pull request's merge commit stays reachable even after the base is rewritten.
    for (n, state, _, merge) in &rows {
        if let (true, Some(m)) = (state == "merged", merge) {
            if kept.get(&merge_ref(*n)) != Some(m) {
                retain_at(git, dir, &merge_ref(*n), m)?;
            }
        }
    }
    for p in open_pulls(conn, repo_id)? {
        // Reopened without its branch: the stored head is the only anchor left.
        if p.head_gone && kept.get(&retention_ref(p.number)) != Some(&p.head_sha) {
            retain(git, dir, p.number, &p.head_sha)?;
        }
    }
    for (n, (state, final_head)) in &known {
        if state != "open" {
            if let Some(h) = final_head {
                if kept.get(&retention_ref(*n)) != Some(h) {
                    retain(git, dir, *n, h)?;
                }
            }
        }
    }
    for name in kept.keys() {
        let n = name
            .strip_prefix("refs/forge/pull/")
            .and_then(|r| r.strip_suffix("/head").or_else(|| r.strip_suffix("/merge")))
            .and_then(|n| n.parse::<i64>().ok());
        if n.is_some_and(|n| !known.contains_key(&n)) {
            let _ = git.run(&Spec {
                repo: Some(dir),
                args: &["update-ref", "-d", name],
                ..Default::default()
            });
        }
    }
    Ok(())
}

/// Does a ref still hold every commit a pull request row names? The check before anything is
/// pruned, independent of how [`reconcile_repo`] went (a sync logs and skips a PR it cannot
/// repair): an open PR needs its head branch or its retention ref at the stored head; a closed or
/// merged one its retention ref at the final head; a merged one also its merge ref.
pub fn verify_roots(conn: &Connection, git: &Git, dir: &Path, repo_id: i64) -> Result<(), String> {
    let e = |e: &dyn std::fmt::Display| e.to_string();
    let kept = refs_under(git, dir, "refs/forge/pull").map_err(|x| e(&x))?;
    let heads = refs_under(git, dir, "refs/heads").map_err(|x| e(&x))?;
    let mut st = conn
        .prepare("SELECT number FROM pulls WHERE repo_id = ?1")
        .map_err(|x| e(&x))?;
    let numbers: Vec<i64> = st
        .query_map([repo_id], |r| r.get(0))
        .map_err(|x| e(&x))?
        .collect::<rusqlite::Result<_>>()
        .map_err(|x| e(&x))?;
    for n in numbers {
        let Some(p) = find(conn, repo_id, n).map_err(|x| e(&x))? else {
            continue;
        };
        let held = |r: String, want: &str| kept.get(&r).is_some_and(|have| have == want);
        let ok = match p.state.as_str() {
            "open" => {
                (!p.head_gone && head_tip(&heads, &p.head_ref).is_some())
                    || held(retention_ref(n), &p.head_sha)
            }
            _ => p
                .final_head
                .as_deref()
                .is_none_or(|h| held(retention_ref(n), h)),
        };
        let merge_ok = p.state != "merged"
            || p.merge_commit
                .as_deref()
                .is_none_or(|m| held(merge_ref(n), m));
        if !ok || !merge_ok {
            return Err(format!("pull request {n} is not held by a ref"));
        }
    }
    Ok(())
}

/// Run [`sync_locked`] under the repository's write gate (for callers that do not hold it, such
/// as the git transport after an accepted push). Failures are logged: the next sync repairs them.
pub fn sync(life: &Lifecycle, conn: &Connection, repo_id: i64, now: i64) {
    match life.with_write_row(conn, repo_id, Duration::from_secs(10), |_| {
        sync_locked(conn, &life.git, &life.repo_dir(repo_id), repo_id, now)
    }) {
        Ok(WriteRun::Ran(Ok(_))) | Ok(WriteRun::Gone) => {}
        Ok(WriteRun::Ran(Err(e))) => {
            eprintln!("sc-forge: pull request sync of repository {repo_id} failed: {e}")
        }
        Ok(WriteRun::Busy) => {
            eprintln!(
                "sc-forge: pull request sync of repository {repo_id} skipped: repository busy"
            )
        }
        Err(e) => eprintln!("sc-forge: pull request sync of repository {repo_id} failed: {e}"),
    }
}

/// Startup: repair every live repository that has pull requests (before the listener is bound,
/// so nothing else is running).
pub fn reconcile_all(life: &Lifecycle, conn: &Connection, now: i64) {
    // Every live repository, not only those with pull requests: an orphan ref from a crash during
    // a repository's first PR creation has no row to find it by.
    let repos = match crate::repos::list_in_state(conn, "live") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sc-forge: pull request reconcile could not list repositories: {e}");
            return;
        }
    };
    for r in repos {
        if let Err(e) = reconcile_repo(conn, &life.git, &life.repo_dir(r.id), r.id, now) {
            eprintln!(
                "sc-forge: pull request reconcile of repository {} failed: {e}",
                r.id
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> (Connection, std::path::PathBuf, i64, i64) {
        let d = std::env::temp_dir().join(format!(
            "scl-forge-pulls-{}-{}",
            std::process::id(),
            crate::timefmt::now()
        ));
        let _ = std::fs::remove_dir_all(&d);
        let conn = crate::db::open_for_admin(&d).unwrap();
        let owner = crate::store::create_account(
            &conn,
            &crate::store::NewAccount {
                login: "o".into(),
                visibility: "public".into(),
                ..Default::default()
            },
            1,
        )
        .unwrap();
        let repo = crate::repos::insert_creating(&conn, owner.id, "r", "main", "", "", 1).unwrap();
        (conn, d, repo.id, owner.id)
    }

    #[test]
    fn numbers_are_sequential_and_one_open_pull_per_target_pair() {
        let (c, d, repo, user) = conn();
        let a = insert(&c, repo, "f", "main", "b1", "h1", "t", "", user, 5).unwrap();
        let b = insert(&c, repo, "g", "main", "b1", "h2", "t", "", user, 6).unwrap();
        assert_eq!((a.number, b.number), (1, 2));
        assert!(
            insert(&c, repo, "f", "main", "b1", "h3", "t", "", user, 7).is_err(),
            "the partial unique index refuses a second open PR with the same targets"
        );
        let mut a2 = a.clone();
        a2.state = "closed".into();
        save(&c, &a2).unwrap();
        assert!(insert(&c, repo, "f", "main", "b1", "h3", "t", "", user, 8).is_ok());
        let (rows, total) = list(&c, repo, &["open", "closed"], Sort::Newest, 0, 2).unwrap();
        assert_eq!((rows.len(), total), (2, 3));
        assert_eq!(rows[0].number, 3);
        let (rows, _) = list(&c, repo, &["closed"], Sort::Oldest, 0, 10).unwrap();
        assert_eq!(rows.len(), 1);
        std::fs::remove_dir_all(&d).unwrap();
        assert!(!d.exists());
    }
}
