//! Merging a pull request: `POST /pulls/{n}/merge`, the merge journal and its crash recovery.
//!
//! Git and SQLite cannot commit together, so a merge is journaled. Under the repository's write
//! gate the handler (1) settles any pending intent, (2) re-reads the PR, the protection rules and
//! the required statuses, (3) computes the merge commit with `merge-tree --write-tree` and
//! `commit-tree`, (4) writes a `pending` intent row, (5) runs ONE `update-ref --stdin` transaction
//! that `verify`s the head and moves the base branch compare-and-swap, (6) records the landing in
//! `refs/forge/merge/<intent>/landed`, and (7) marks the intent done and the PR merged in one
//! SQLite transaction.
//!
//! Git's files backend commits several refs one after another, so no single transaction can both
//! move the base and create a marker crash-atomically. The protocol is therefore built from steps
//! that are each atomic and from evidence that survives a crash between them. A pending intent
//! has landed when (a) its `landed` marker exists (definitive, even if the base was rewritten
//! afterwards), or (b) its merge commit is an ancestor of the base branch (the crash fell between
//! (5) and (6); at startup nobody can have rewritten the base yet). Otherwise it did not land, and
//! is aborted unless a lock file shows a git writer still holding the base ref (the intent then
//! stays pending until that writer is gone). An unreadable answer never aborts: the intent stays
//! pending.

use crate::api::{body, str_field};
use crate::gitproc::{Git, GitError, Identity, Spec};
use crate::gitwrite as gw;
use crate::http::{error, Resp};
use crate::pulls::{self, ComputeError};
use crate::pulls_api::{find, gated, missing, needs_write, number, tip};
use crate::refname;
use crate::repo_api::acc;
use crate::repos::{Access, Perm};
use crate::routes::Ctx;
use crate::statuses;
use crate::timefmt::now;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::path::Path;
use std::time::Duration;

/// Rounds a merge takes when the base branch moves under it, then it answers "try again later".
const ATTEMPTS: usize = 3;
/// Conflicting paths named in a refusal.
const NAMED_PATHS: usize = 10;

/// The marker ref that says intent `id` landed.
pub fn landed_ref(id: i64) -> String {
    format!("refs/forge/merge/{id}/landed")
}

/// One journal row.
#[derive(Clone, Debug)]
pub struct Intent {
    pub id: i64,
    pub repo_id: i64,
    pub pull_number: i64,
    pub base_ref: String,
    pub head_ref: String,
    pub base_oid: String,
    pub head_oid: String,
    pub merge_oid: String,
    pub merge_base: String,
    pub changed_files: i64,
    pub additions: i64,
    pub deletions: i64,
    pub merger_id: i64,
    pub merged_unix: i64,
}

const COLS: &str =
    "id, repo_id, pull_number, base_ref, head_ref, base_oid, head_oid, merge_oid, merge_base, \
    changed_files, additions, deletions, merger_id, merged_unix";

fn row(r: &rusqlite::Row) -> rusqlite::Result<Intent> {
    Ok(Intent {
        id: r.get(0)?,
        repo_id: r.get(1)?,
        pull_number: r.get(2)?,
        base_ref: r.get(3)?,
        head_ref: r.get(4)?,
        base_oid: r.get(5)?,
        head_oid: r.get(6)?,
        merge_oid: r.get(7)?,
        merge_base: r.get(8)?,
        changed_files: r.get(9)?,
        additions: r.get(10)?,
        deletions: r.get(11)?,
        merger_id: r.get(12)?,
        merged_unix: r.get(13)?,
    })
}

/// Pending intents of the repository.
pub fn pending(conn: &Connection, repo_id: i64) -> rusqlite::Result<Vec<Intent>> {
    let mut st = conn.prepare(&format!(
        "SELECT {COLS} FROM merge_intents WHERE repo_id = ?1 AND state = 'pending' ORDER BY id"
    ))?;
    let rows = st.query_map([repo_id], row)?.collect();
    rows
}

/// Is a merge of this repository unfinished? A database error reads as "no": callers that must
/// fail closed use [`pending_checked`].
pub fn has_pending(conn: &Connection, repo_id: i64) -> bool {
    pending_checked(conn, repo_id).unwrap_or(false)
}

/// [`has_pending`] that reports a database error instead of answering "no".
pub fn pending_checked(conn: &Connection, repo_id: i64) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT 1 FROM merge_intents WHERE repo_id = ?1 AND state = 'pending' LIMIT 1",
        [repo_id],
        |_| Ok(()),
    )
    .optional()
    .map(|r| r.is_some())
}

fn insert(conn: &Connection, i: &Intent, now: i64) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO merge_intents (repo_id, pull_number, base_ref, head_ref, base_oid, head_oid, merge_oid, \
         merge_base, changed_files, additions, deletions, merger_id, merged_unix, state, created_unix) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'pending', ?14)",
        params![
            i.repo_id,
            i.pull_number,
            i.base_ref,
            i.head_ref,
            i.base_oid,
            i.head_oid,
            i.merge_oid,
            i.merge_base,
            i.changed_files,
            i.additions,
            i.deletions,
            i.merger_id,
            i.merged_unix,
            now
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// A retry builds a new merge commit on the new base (and, when the client named no head, from
/// whatever the head is by then), with its own merge base, statistics and time: the journal says
/// all of it, the head included, before the ref moves, so recovery writes exactly what a
/// normal completion would.
fn retarget(conn: &Connection, i: &Intent) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE merge_intents SET base_oid = ?1, merge_oid = ?2, merge_base = ?3, changed_files = ?4, \
         additions = ?5, deletions = ?6, merged_unix = ?7, head_oid = ?9 WHERE id = ?8 AND state = 'pending'",
        params![
            i.base_oid,
            i.merge_oid,
            i.merge_base,
            i.changed_files,
            i.additions,
            i.deletions,
            i.merged_unix,
            i.id,
            i.head_oid
        ],
    )?;
    Ok(())
}

fn abort(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE merge_intents SET state = 'aborted' WHERE id = ?1 AND state = 'pending'",
        [id],
    )?;
    Ok(())
}

/// The merge landed: the PR becomes merged and the intent done, in one transaction. Idempotent: a
/// PR already merged by this very commit is fine. A PR in any other state is an inconsistency and
/// fails the transaction, so the intent (and its evidence) stays pending instead of being consumed.
fn finalize_rows(conn: &Connection, i: &Intent, recovered: bool) -> rusqlite::Result<()> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE pulls SET state = 'merged', merge_commit_sha = ?1, final_head_sha = ?2, head_sha = ?2, \
         base_sha = ?3, merged_unix = ?4, closed_unix = ?4, updated_unix = ?4, merged_by = ?5, \
         merge_base = ?6, changed_files = ?7, additions = ?8, deletions = ?9, head_gone = 0 \
         WHERE repo_id = ?10 AND number = ?11 AND state = 'open' AND base_ref = ?12 AND head_ref = ?13",
        params![
            i.merge_oid,
            i.head_oid,
            i.base_oid,
            i.merged_unix,
            i.merger_id,
            i.merge_base,
            i.changed_files,
            i.additions,
            i.deletions,
            i.repo_id,
            i.pull_number,
            i.base_ref,
            i.head_ref
        ],
    )?;
    if changed == 0 {
        let same: bool = tx
            .query_row(
                "SELECT 1 FROM pulls WHERE repo_id = ?1 AND number = ?2 AND state = 'merged' AND merge_commit_sha = ?3",
                params![i.repo_id, i.pull_number, i.merge_oid],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !same {
            return Err(rusqlite::Error::StatementChangedRows(0));
        }
    }
    tx.execute(
        "UPDATE merge_intents SET state = 'done', recovered = ?2 WHERE id = ?1 AND state = 'pending'",
        params![i.id, recovered],
    )?;
    tx.commit()
}

/// Finish a landed merge: keep the head reachable, mark the rows, drop the marker. The SQLite step
/// is retried a few times while the caller still holds the gate; if it still fails the intent stays
/// pending (its evidence is intact) and the next gated operation or read completes it.
fn finish(
    conn: &Connection,
    git: &Git,
    dir: &Path,
    i: &Intent,
    recovered: bool,
) -> Result<(), ComputeError> {
    if let Err(e) = pulls::retain(git, dir, i.pull_number, &i.head_oid) {
        eprintln!(
            "sc-forge: could not retain the head of merged pull request {}: {e}",
            i.pull_number
        );
    }
    // The marker goes below; from here on this ref is what keeps the merge commit alive when the
    // base is rewritten away from it.
    if let Err(e) = pulls::retain_at(git, dir, &pulls::merge_ref(i.pull_number), &i.merge_oid) {
        eprintln!(
            "sc-forge: could not retain the merge commit of pull request {}: {e}",
            i.pull_number
        );
    }
    let mut last = None;
    for k in 0..3 {
        match finalize_rows(conn, i, recovered) {
            Ok(()) => {
                last = None;
                break;
            }
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(20 * (k + 1)));
            }
        }
    }
    if let Some(e) = last {
        return Err(e.into());
    }
    let _ = crate::repos::touch(conn, i.repo_id, i.merged_unix);
    // The marker has done its job.
    let _ = git.run(&Spec {
        repo: Some(dir),
        args: &["update-ref", "-d", &landed_ref(i.id)],
        ..Default::default()
    });
    Ok(())
}

/// Does the commit exist in the repository?
pub(crate) fn commit_exists(git: &Git, dir: &Path, oid: &str) -> Result<bool, GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &["cat-file", "-e", &format!("{oid}^{{commit}}")],
        ..Default::default()
    })?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        // Anything else is "could not tell", which never aborts an intent.
        _ => Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        )),
    }
}

/// Has the intent's merge landed? The marker says so definitively; failing that, the merge commit
/// being part of the base branch's history does. `Err` is "could not tell", never "no".
fn is_landed(git: &Git, dir: &Path, i: &Intent) -> Result<bool, GitError> {
    if gw::read_ref(git, dir, &landed_ref(i.id))?.is_some() {
        return Ok(true);
    }
    let Some(tip) = gw::read_ref(git, dir, &refname::branch_ref(&i.base_ref))? else {
        return Ok(false);
    };
    if !commit_exists(git, dir, &i.merge_oid)? {
        return Ok(false);
    }
    gw::is_ancestor(git, dir, &i.merge_oid, &tip)
}

/// Record that the intent landed. Best effort: ancestry carries the same fact until it is written.
fn mark_landed(git: &Git, dir: &Path, i: &Intent) {
    let zero = "0".repeat(i.merge_oid.len());
    let _ = git.run(&Spec {
        repo: Some(dir),
        args: &["update-ref", &landed_ref(i.id), &i.merge_oid, &zero],
        ..Default::default()
    });
}

/// Is a git writer holding the base ref right now (its lock file exists)? At run time that is a
/// live writer (a push, or our own publish): the intent waits rather than being judged under it.
/// The lock of a *dead* writer is cleared at startup (`orphans::sweep`) or by the maintenance pass
/// once its writers are excluded (`orphans::clean_repo`), not guessed at here.
fn base_is_locked(dir: &Path, base_ref: &str) -> bool {
    dir.join("refs")
        .join("heads")
        .join(format!("{base_ref}.lock"))
        .exists()
}

/// Settle the pending intents of the repository, with the write gate held (or at startup, when
/// nothing else runs). Landed ones are finalized from the journal; ones that did not land are
/// aborted; ones whose outcome cannot be told yet (a git writer holds the base, or git failed) stay
/// pending. Returns how many were finalized.
pub fn recover_locked(
    conn: &Connection,
    git: &Git,
    dir: &Path,
    repo_id: i64,
) -> Result<usize, ComputeError> {
    let mut done = 0;
    for i in pending(conn, repo_id)? {
        if is_landed(git, dir, &i)? {
            mark_landed(git, dir, &i);
            finish(conn, git, dir, &i, true)?;
            done += 1;
        } else if !base_is_locked(dir, &i.base_ref) {
            // A writer that committed between the first look and the lock check has also dropped its
            // lock: look once more before an abort is final.
            if is_landed(git, dir, &i)? {
                mark_landed(git, dir, &i);
                finish(conn, git, dir, &i, true)?;
                done += 1;
            } else {
                abort(conn, i.id)?;
            }
        }
    }
    Ok(done)
}

/// Remove marker refs that belong to no pending intent (a finished merge whose cleanup was lost).
pub fn drop_stale_receipts(
    conn: &Connection,
    git: &Git,
    dir: &Path,
    repo_id: i64,
) -> Result<(), ComputeError> {
    let live: Vec<String> = pending(conn, repo_id)?
        .iter()
        .map(|i| landed_ref(i.id))
        .collect();
    for name in pulls::refs_under(git, dir, "refs/forge/merge")?.keys() {
        if !live.contains(name) {
            let _ = git.run(&Spec {
                repo: Some(dir),
                args: &["update-ref", "-d", name],
                ..Default::default()
            });
        }
    }
    Ok(())
}

// ---- git steps ----

/// The result of `merge-tree --write-tree`.
enum Tree {
    Clean(String),
    Conflict(Vec<String>),
}

fn merge_tree(git: &Git, dir: &Path, base: &str, head: &str) -> Result<Tree, GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &[
            "merge-tree",
            "--write-tree",
            "--name-only",
            "--no-messages",
            "-z",
            "--end-of-options",
            base,
            head,
        ],
        ..Default::default()
    })?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut toks = text.split('\0');
    let tree = toks.next().unwrap_or("").trim().to_string();
    match out.status.code() {
        Some(0) if !tree.is_empty() => Ok(Tree::Clean(tree)),
        Some(1) => {
            let mut names: Vec<String> = Vec::new();
            for t in toks {
                if t.is_empty() {
                    break;
                }
                if !names.iter().any(|n| n == t) {
                    names.push(t.to_string());
                }
            }
            Ok(Tree::Conflict(names))
        }
        _ => Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        )),
    }
}

fn commit_tree(
    git: &Git,
    dir: &Path,
    tree: &str,
    base: &str,
    head: &str,
    message: &str,
    id: &Identity,
) -> Result<String, GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &["commit-tree", tree, "-p", base, "-p", head],
        stdin: Some(message.as_bytes()),
        identity: Some(id),
        ..Default::default()
    })?;
    if out.ok() {
        Ok(out.text())
    } else {
        Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

/// The ref transaction: the head is verified and the base moves compare-and-swap, together. One
/// ref changes, so it commits or it does not. `Ok(false)`: it did not commit, or we cannot tell
/// (a timeout); the caller asks [`is_landed`].
fn publish(git: &Git, dir: &Path, i: &Intent) -> Result<bool, GitError> {
    let script = format!(
        "start\nverify {head} {head_oid}\nupdate {base} {merge} {base_oid}\nprepare\ncommit\n",
        head = refname::branch_ref(&i.head_ref),
        head_oid = i.head_oid,
        base = refname::branch_ref(&i.base_ref),
        merge = i.merge_oid,
        base_oid = i.base_oid,
    );
    match git.run(&Spec {
        repo: Some(dir),
        args: &["update-ref", "--stdin"],
        stdin: Some(script.as_bytes()),
        ..Default::default()
    }) {
        Ok(o) => Ok(o.ok()),
        // Killed by the runner's deadline. SIGKILL leaves the locks of the refs it had prepared; they
        // stay until the next restart or maintenance pass cleans them, because a lock cannot be told
        // from a live writer's here (the intent stays pending while the base is locked).
        Err(GitError::Timeout { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Test-only knob: `SC_FORGE_MERGE_PAUSE_MS` stretches the two crash windows of a merge (after the
/// journal row, and after the base moved) so a test can SIGKILL the server inside them. Unset in
/// production.
fn pause_for_tests() {
    if let Some(ms) = std::env::var("SC_FORGE_MERGE_PAUSE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        std::thread::sleep(Duration::from_millis(ms.min(5_000)));
    }
}

// ---- the handler ----

fn try_later(ctx: &Ctx) -> Resp {
    error(&ctx.app.base, 405, "Please try again later")
}

fn stale_head(ctx: &Ctx) -> Resp {
    error(&ctx.app.base, 409, "head out of date")
}

fn internal<E: std::fmt::Display>(ctx: &Ctx, e: E) -> Resp {
    ctx.app.internal(&e)
}

fn conflict(ctx: &Ctx, paths: &[String]) -> Resp {
    let shown: Vec<&str> = paths.iter().take(NAMED_PATHS).map(String::as_str).collect();
    let more = paths.len().saturating_sub(shown.len());
    let mut list = shown.join(", ");
    if more > 0 {
        list.push_str(&format!(" and {more} more"));
    }
    error(&ctx.app.base, 409, &format!("Merge conflict: {list}"))
}

/// `POST /repos/{o}/{r}/pulls/{n}/merge`.
pub fn merge_pull(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    if a.perm < Perm::Write {
        return needs_write(ctx);
    }
    let Some(n) = number(ctx.param("n")) else {
        return missing(ctx);
    };
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    match str_field(&b, "Do").unwrap_or_default().as_str() {
        "merge" => {}
        "" => return error(&ctx.app.base, 422, "[Do]: Required"),
        "squash" | "rebase" | "rebase-merge" | "fast-forward-only" | "manually-merged" => {
            return error(&ctx.app.base, 422, "only Do=merge is supported")
        }
        _ => return error(&ctx.app.base, 422, "[Do]: In"),
    }
    let want_head = str_field(&b, "head_commit_id").filter(|s| !s.is_empty());
    gated(ctx, &a, || run(ctx, &a, n, want_head.as_deref()))
}

fn run(ctx: &Ctx, a: &Access, n: i64, want_head: Option<&str>) -> Resp {
    // `gated` has settled whatever an earlier merge left; nothing else can be pending now.
    let mut intent_id: Option<i64> = None;
    let outcome = attempt_loop(ctx, a, n, want_head, &mut intent_id);
    // Any exit that did not land leaves the intent for the same judgement recovery makes; a
    // landed one is already done, an unknown one stays pending.
    if intent_id.is_some() {
        let (git, dir) = (&ctx.app.life.git, ctx.app.life.repo_dir(a.repo.id));
        if let Err(e) = recover_locked(ctx.conn, git, &dir, a.repo.id) {
            eprintln!(
                "sc-forge: could not settle a merge of repository {}: {e}",
                a.repo.id
            );
        }
    }
    outcome
}

fn attempt_loop(
    ctx: &Ctx,
    a: &Access,
    n: i64,
    want_head: Option<&str>,
    intent_id: &mut Option<i64>,
) -> Resp {
    let (git, dir) = (&ctx.app.life.git, ctx.app.life.repo_dir(a.repo.id));
    let user = &ctx.who.user;
    for round in 0..ATTEMPTS {
        // Re-read everything each round: the PR, the rules, both tips, the statuses.
        let p = match find(ctx, a, n) {
            Ok(p) => p,
            Err(r) => return r,
        };
        match p.state.as_str() {
            "merged" => return error(&ctx.app.base, 405, "The PR is already merged"),
            "closed" => return missing(ctx),
            _ => {}
        }
        let (base_oid, head_oid) = match (tip(ctx, a, &p.base_ref), tip(ctx, a, &p.head_ref)) {
            (Ok(Some(b)), Ok(Some(h))) => (b, h),
            (Ok(_), Ok(_)) => return missing(ctx),
            (Err(r), _) | (_, Err(r)) => return r,
        };
        if want_head.is_some_and(|w| !w.eq_ignore_ascii_case(&head_oid)) {
            return stale_head(ctx);
        }
        if gw::is_ancestor(git, &dir, &head_oid, &base_oid).unwrap_or(false) {
            return try_later(ctx);
        }
        let rules = match crate::protection::load(ctx.conn, a.repo.id) {
            Ok(r) => r,
            Err(e) => return internal(ctx, e),
        };
        if let Some(rule) = rules
            .for_branch(&p.base_ref)
            .filter(|r| r.enable_status_check)
        {
            let latest = match statuses::latest(ctx.conn, a.repo.id, &head_oid) {
                Ok(l) => l,
                Err(e) => return internal(ctx, e),
            };
            let required = rule.contexts.clone().unwrap_or_default();
            // A rule that requires checks but names none cannot be satisfied: fail closed.
            if required.is_empty() || !required.iter().all(|c| statuses::satisfied(&latest, c)) {
                return error(
                    &ctx.app.base,
                    405,
                    "not allowed to merge [reason: Not all required status checks successful]",
                );
            }
        }
        let facts = match pulls::compute(ctx.conn, git, &dir, a.repo.id, &base_oid, &head_oid) {
            Ok(c) => c,
            Err(ComputeError::Db(e)) => return internal(ctx, e),
            Err(ComputeError::Git(e)) => return crate::content_api::read_err(ctx, a, e),
        };
        let Some(merge_base) = facts.merge_base.clone() else {
            return error(&ctx.app.base, 409, "Merge conflict: unrelated histories");
        };
        let tree = match merge_tree(git, &dir, &base_oid, &head_oid) {
            Ok(Tree::Clean(t)) => t,
            Ok(Tree::Conflict(paths)) => return conflict(ctx, &paths),
            Err(e) => return crate::content_api::read_err(ctx, a, e),
        };
        let when = now();
        let email = crate::content_write::commit_email(user);
        let Some(identity) = Identity::new(&user.login, &email).map(|i| i.at(when)) else {
            return internal(ctx, "unusable commit identity");
        };
        // One line, whatever the title holds: a newline would add body or trailer lines (a fake
        // `Signed-off-by`) to a commit written under the merger's identity, and a NUL would make
        // `commit-tree` fail for good.
        let title: String = p
            .title
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let message = format!(
            "Merge pull request '{}' (#{}) from {} into {}\n",
            title, p.number, p.head_ref, p.base_ref
        );
        let merge_oid =
            match commit_tree(git, &dir, &tree, &base_oid, &head_oid, &message, &identity) {
                Ok(o) => o,
                Err(e) => return crate::content_api::read_err(ctx, a, e),
            };
        let mut intent = Intent {
            id: 0,
            repo_id: a.repo.id,
            pull_number: p.number,
            base_ref: p.base_ref.clone(),
            head_ref: p.head_ref.clone(),
            base_oid: base_oid.clone(),
            head_oid: head_oid.clone(),
            merge_oid: merge_oid.clone(),
            merge_base,
            changed_files: facts.changed_files,
            additions: facts.additions,
            deletions: facts.deletions,
            merger_id: user.id,
            merged_unix: when,
        };
        // The journal first, and again (every field) whenever the merge commit changes.
        match *intent_id {
            None => match insert(ctx.conn, &intent, when) {
                Ok(id) => {
                    *intent_id = Some(id);
                    intent.id = id;
                }
                Err(e) => return internal(ctx, e),
            },
            Some(id) => {
                intent.id = id;
                if let Err(e) = retarget(ctx.conn, &intent) {
                    return internal(ctx, e);
                }
            }
        }
        pause_for_tests();
        // Whether the transaction committed is asked of git, not read off an exit status; an
        // answer that cannot be had leaves the intent pending and the request failed.
        let committed = publish(git, &dir, &intent).unwrap_or(false);
        let landed = committed
            || match is_landed(git, &dir, &intent) {
                Ok(l) => l,
                Err(e) => return crate::content_api::read_err(ctx, a, e),
            };
        if landed {
            mark_landed(git, &dir, &intent);
            pause_for_tests();
            return match finish(ctx.conn, git, &dir, &intent, false) {
                Ok(()) => {
                    let mut r = Resp::json(200, &serde_json::Value::Null);
                    r.body = Vec::new();
                    r
                }
                Err(e) => internal(ctx, e),
            };
        }
        // Not published. Why: the head moved (the client's id is stale), the base moved (rebuild on
        // the new tip), or something transient.
        let (head2, base2) = (tip(ctx, a, &p.head_ref), tip(ctx, a, &p.base_ref));
        if let (Ok(Some(h2)), Ok(Some(b2))) = (&head2, &base2) {
            if *h2 != head_oid {
                return stale_head(ctx);
            }
            if *b2 == base_oid && round + 1 == ATTEMPTS {
                return try_later(ctx);
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    try_later(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Connection, std::path::PathBuf, i64, i64) {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "scl-forge-merges-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
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

    fn intent(repo: i64, user: i64, n: i64) -> Intent {
        Intent {
            id: 0,
            repo_id: repo,
            pull_number: n,
            base_ref: "main".into(),
            head_ref: "f".into(),
            base_oid: "b".repeat(40),
            head_oid: "a".repeat(40),
            merge_oid: "c".repeat(40),
            merge_base: "d".repeat(40),
            changed_files: 2,
            additions: 3,
            deletions: 1,
            merger_id: user,
            merged_unix: 77,
        }
    }

    #[test]
    fn finalizing_writes_every_field_a_normal_merge_does_and_is_idempotent() {
        let (c, d, repo, user) = fixture();
        pulls::insert(&c, repo, "f", "main", "b", "h", "t", "", user, 5).unwrap();
        let id = insert(&c, &intent(repo, user, 1), 6).unwrap();
        assert!(has_pending(&c, repo));
        let mut i = intent(repo, user, 1);
        i.id = id;
        finalize_rows(&c, &i, false).unwrap();
        finalize_rows(&c, &i, false).unwrap();
        let p = pulls::find(&c, repo, 1).unwrap().unwrap();
        assert_eq!(p.state, "merged");
        assert_eq!(p.merge_commit.as_deref(), Some(i.merge_oid.as_str()));
        assert_eq!(p.final_head.as_deref(), Some(i.head_oid.as_str()));
        assert_eq!(
            (p.merged, p.merged_by, p.closed),
            (Some(77), Some(user), Some(77))
        );
        assert_eq!(
            (p.changed_files, p.additions, p.deletions),
            (Some(2), Some(3), Some(1))
        );
        assert_eq!(p.merge_base.as_deref(), Some(i.merge_base.as_str()));
        assert!(!has_pending(&c, repo));
        std::fs::remove_dir_all(&d).unwrap();
        assert!(!d.exists());
    }

    #[test]
    fn one_pending_intent_per_pull_and_retarget_changes_only_the_commit() {
        let (c, d, repo, user) = fixture();
        pulls::insert(&c, repo, "f", "main", "b", "h", "t", "", user, 5).unwrap();
        let id = insert(&c, &intent(repo, user, 1), 6).unwrap();
        assert!(insert(&c, &intent(repo, user, 1), 7).is_err());
        let mut again = intent(repo, user, 1);
        again.id = id;
        again.base_oid = "e".repeat(40);
        again.merge_oid = "f".repeat(40);
        again.merge_base = "9".repeat(40);
        (again.changed_files, again.additions, again.deletions) = (5, 6, 7);
        again.merged_unix = 99;
        again.head_oid = "8".repeat(40);
        retarget(&c, &again).unwrap();
        let p = pending(&c, repo).unwrap();
        assert_eq!(
            (
                p[0].base_oid.clone(),
                p[0].merge_oid.clone(),
                p[0].merge_base.clone()
            ),
            ("e".repeat(40), "f".repeat(40), "9".repeat(40))
        );
        assert_eq!(
            (
                p[0].changed_files,
                p[0].additions,
                p[0].deletions,
                p[0].merged_unix
            ),
            (5, 6, 7, 99),
            "a retry persists every fact it recomputed"
        );
        assert_eq!(p[0].head_oid, "8".repeat(40), "and the head it built on");
        abort(&c, id).unwrap();
        assert!(
            insert(&c, &intent(repo, user, 1), 8).is_ok(),
            "an aborted intent frees the slot"
        );
        std::fs::remove_dir_all(&d).unwrap();
        assert!(!d.exists());
    }
}
