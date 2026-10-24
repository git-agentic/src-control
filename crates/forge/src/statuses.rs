//! Commit statuses: `POST /statuses/{sha}`, the history lists and the combined status.
//!
//! Any caller with write access may post any context (Gitea's trust boundary: the writer is
//! trusted, a context is not an attestation). "Latest" per context is the highest id. Storage is
//! bounded per commit: at most [`MAX_CONTEXTS`] distinct contexts and [`MAX_HISTORY`] rows per
//! context (the oldest rows go), a departure from Gitea, which keeps everything. The merge gate
//! reads [`latest`] directly, never the paged combined view.

use crate::api::{body, link_header, page_params, paged};
use crate::content_api::{api_base, dir};
use crate::gitobj::{self, Peel};
use crate::http::{error, not_found, Resp};
use crate::repo_api::{acc, read_locked, repo_json};
use crate::repos::{Access, Perm};
use crate::routes::Ctx;
use crate::store;
use crate::timefmt::{now, rfc3339};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use std::collections::HashMap;

pub const STATES: &[&str] = &[
    "pending", "success", "error", "failure", "warning", "skipped",
];
/// Distinct contexts per commit.
pub const MAX_CONTEXTS: i64 = 100;
/// Rows kept per (commit, context).
pub const MAX_HISTORY: i64 = 100;
const MAX_CONTEXT: usize = 1024;
const MAX_DESCRIPTION: usize = 1024;
const MAX_URL: usize = 2048;

/// A stored status.
#[derive(Clone, Debug)]
pub struct Status {
    pub id: i64,
    pub sha: String,
    pub context: String,
    pub state: String,
    pub description: String,
    pub target_url: String,
    pub creator_id: i64,
    pub created: i64,
    pub updated: i64,
}

const COLS: &str =
    "id, sha, context, state, description, target_url, creator_id, created_unix, updated_unix";

fn row(r: &rusqlite::Row) -> rusqlite::Result<Status> {
    Ok(Status {
        id: r.get(0)?,
        sha: r.get(1)?,
        context: r.get(2)?,
        state: r.get(3)?,
        description: r.get(4)?,
        target_url: r.get(5)?,
        creator_id: r.get(6)?,
        created: r.get(7)?,
        updated: r.get(8)?,
    })
}

/// How an insert ended.
pub enum Inserted {
    Done(Status),
    /// The commit already has [`MAX_CONTEXTS`] distinct contexts and this one is new.
    TooManyContexts,
}

/// Insert a status and trim the context's history, in one immediate transaction (so concurrent
/// posters cannot both pass the context cap).
#[allow(clippy::too_many_arguments)]
pub fn insert(
    conn: &Connection,
    repo_id: i64,
    sha: &str,
    context: &str,
    state: &str,
    description: &str,
    target_url: &str,
    creator_id: i64,
    now: i64,
) -> rusqlite::Result<Inserted> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let known: i64 = tx.query_row(
        "SELECT COUNT(*) FROM commit_statuses WHERE repo_id = ?1 AND sha = ?2 AND context = ?3",
        params![repo_id, sha, context],
        |r| r.get(0),
    )?;
    if known == 0 {
        let contexts: i64 = tx.query_row(
            "SELECT COUNT(DISTINCT context) FROM commit_statuses WHERE repo_id = ?1 AND sha = ?2",
            params![repo_id, sha],
            |r| r.get(0),
        )?;
        if contexts >= MAX_CONTEXTS {
            return Ok(Inserted::TooManyContexts);
        }
    }
    tx.execute(
        "INSERT INTO commit_statuses (repo_id, sha, context, state, description, target_url, \
         creator_id, created_unix, updated_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
        params![
            repo_id,
            sha,
            context,
            state,
            description,
            target_url,
            creator_id,
            now
        ],
    )?;
    let id = tx.last_insert_rowid();
    tx.execute(
        "DELETE FROM commit_statuses WHERE repo_id = ?1 AND sha = ?2 AND context = ?3 AND id NOT IN \
         (SELECT id FROM commit_statuses WHERE repo_id = ?1 AND sha = ?2 AND context = ?3 \
          ORDER BY id DESC LIMIT ?4)",
        params![repo_id, sha, context, MAX_HISTORY],
    )?;
    let s = tx.query_row(
        &format!("SELECT {COLS} FROM commit_statuses WHERE id = ?1"),
        [id],
        row,
    )?;
    tx.commit()?;
    Ok(Inserted::Done(s))
}

/// Every status of the commit, newest first.
pub fn history(conn: &Connection, repo_id: i64, sha: &str) -> rusqlite::Result<Vec<Status>> {
    let mut st = conn.prepare(&format!(
        "SELECT {COLS} FROM commit_statuses WHERE repo_id = ?1 AND sha = ?2 ORDER BY id DESC"
    ))?;
    let rows = st.query_map(params![repo_id, sha], row)?.collect();
    rows
}

/// The latest status of each context of the commit, oldest first (the order Gitea lists them in).
pub fn latest(conn: &Connection, repo_id: i64, sha: &str) -> rusqlite::Result<Vec<Status>> {
    let mut st = conn.prepare(&format!(
        "SELECT {COLS} FROM commit_statuses WHERE id IN \
         (SELECT MAX(id) FROM commit_statuses WHERE repo_id = ?1 AND sha = ?2 GROUP BY context) \
         ORDER BY id"
    ))?;
    let rows = st.query_map(params![repo_id, sha], row)?.collect();
    rows
}

/// The combined state of the latest statuses, as recorded (H): any `error` or `failure` reads
/// `failure`, else any `pending` reads `pending`, else `warning`, else `success`; only `skipped`
/// (or nothing) reads `skipped` / `pending`. The unrecorded combinations (`warning` alone, all
/// `skipped`) follow that severity order.
pub fn combined_state(latest: &[Status]) -> &'static str {
    let any = |s: &str| latest.iter().any(|x| x.state == s);
    if latest.is_empty() {
        "pending"
    } else if any("error") || any("failure") {
        "failure"
    } else if any("pending") {
        "pending"
    } else if any("warning") {
        "warning"
    } else if any("success") {
        "success"
    } else {
        "skipped"
    }
}

/// Does a required context have a `success` or `skipped` latest status? The merge gate's test.
pub fn satisfied(latest: &[Status], context: &str) -> bool {
    latest
        .iter()
        .any(|s| s.context == context && matches!(s.state.as_str(), "success" | "skipped"))
}

fn status_json(
    ctx: &Ctx,
    a: &Access,
    s: &Status,
    creators: &mut HashMap<i64, Value>,
) -> Result<Value, Resp> {
    if let std::collections::hash_map::Entry::Vacant(slot) = creators.entry(s.creator_id) {
        let u = store::find_by_id(ctx.conn, s.creator_id)
            .map_err(|e| ctx.app.internal(&e))?
            .ok_or_else(|| ctx.app.internal(&"status without creator"))?;
        let j = crate::api::nested_user_json(&ctx.app.base, &u, true);
        slot.insert(j);
    }
    Ok(json!({
        "id": s.id,
        "status": s.state,
        "target_url": s.target_url,
        "description": s.description,
        "url": format!("{}/statuses/{}", api_base(ctx, a), s.sha),
        "context": s.context,
        "creator": creators[&s.creator_id],
        "created_at": rfc3339(s.created),
        "updated_at": rfc3339(s.updated),
    }))
}

/// The path of this request below `/api/v1`, as the client sent it: page links repeat it.
fn request_path<'a>(ctx: &'a Ctx) -> &'a str {
    ctx.req
        .path
        .strip_prefix("/api/v1")
        .unwrap_or(&ctx.req.path)
}

fn no_commit(ctx: &Ctx) -> Resp {
    not_found(&ctx.app.base, "The target couldn't be found.", None)
}

/// Resolve `rev` to a commit id in the repository, or answer for it.
fn commit_of(ctx: &Ctx, a: &Access, rev: &str) -> Result<String, Resp> {
    match gitobj::resolve(
        &ctx.app.life.git,
        &dir(ctx, a),
        &a.repo.default_branch,
        rev,
        Peel::Commit,
    ) {
        Ok(Some(r)) => Ok(r.oid),
        Ok(None) => Err(no_commit(ctx)),
        Err(e) => Err(crate::content_api::read_err(ctx, a, e)),
    }
}

fn valid_url(u: &str) -> bool {
    u.is_empty()
        || ((u.starts_with("http://") || u.starts_with("https://"))
            && !u.chars().any(|c| c.is_control() || c.is_whitespace()))
}

/// `POST /repos/{o}/{r}/statuses/{sha..}`.
pub fn create_status(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    if a.perm < Perm::Write {
        return error(
            &ctx.app.base,
            403,
            "user should have a permission to write to a repo",
        );
    }
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let text = |k: &str| match b.get(k) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(format!("[{k}]: must be a string")),
    };
    let (state, context, description, url) = match (
        text("state"),
        text("context"),
        text("description"),
        text("target_url"),
    ) {
        (Ok(s), Ok(c), Ok(d), Ok(u)) => (s, c, d, u),
        (Err(m), ..) | (_, Err(m), ..) | (_, _, Err(m), _) | (_, _, _, Err(m)) => {
            return error(&ctx.app.base, 422, &m)
        }
    };
    if !STATES.contains(&state.as_str()) {
        return error(
            &ctx.app.base,
            422,
            &format!("[State]: must be one of {}", STATES.join(", ")),
        );
    }
    if context.len() > MAX_CONTEXT
        || description.chars().count() > MAX_DESCRIPTION
        || url.len() > MAX_URL
        || !valid_url(&url)
        || context.chars().any(char::is_control)
    {
        return error(
            &ctx.app.base,
            422,
            "[Context/Description/TargetURL]: too long, or not a plain http(s) URL",
        );
    }
    let rev = ctx.param("sha").to_string();
    read_locked(ctx, &a, |ctx| {
        let sha = match commit_of(ctx, &a, &rev) {
            Ok(s) => s,
            Err(r) => return r,
        };
        match insert(
            ctx.conn,
            a.repo.id,
            &sha,
            &context,
            &state,
            &description,
            &url,
            ctx.who.user.id,
            now(),
        ) {
            Ok(Inserted::Done(s)) => match status_json(ctx, &a, &s, &mut HashMap::new()) {
                Ok(v) => Resp::json(201, &v),
                Err(r) => r,
            },
            Ok(Inserted::TooManyContexts) => error(
                &ctx.app.base,
                422,
                &format!("a commit has at most {MAX_CONTEXTS} status contexts"),
            ),
            Err(e) => ctx.app.internal(&e),
        }
    })
}

/// `GET /repos/{o}/{r}/statuses/{ref..}` and `GET /repos/{o}/{r}/commits/{ref}/statuses`: the
/// whole history, newest first, paged.
pub fn list_statuses(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let rev = ctx.param("sha").to_string();
    read_locked(ctx, &a, |ctx| {
        let sha = match commit_of(ctx, &a, &rev) {
            Ok(s) => s,
            Err(r) => return r,
        };
        let all = match history(ctx.conn, a.repo.id, &sha) {
            Ok(v) => v,
            Err(e) => return ctx.app.internal(&e),
        };
        let (page, limit) = page_params(ctx);
        let mut creators = HashMap::new();
        let items: Result<Vec<Value>, Resp> = all
            .iter()
            .skip(((page - 1) * limit) as usize)
            .take(limit as usize)
            .map(|s| status_json(ctx, &a, s, &mut creators))
            .collect();
        match items {
            Ok(items) => paged(ctx, request_path(ctx), all.len() as i64, page, limit, items),
            Err(r) => r,
        }
    })
}

/// `GET /repos/{o}/{r}/commits/{ref}/status`: the latest status per context, with the combined
/// state over all of them; the listed statuses are paged. Only the resolution of the revision
/// runs under the shared lifecycle lock: `repo_json` takes that lock itself, and a second shared
/// acquisition behind a queued exclusive one would deadlock (see `lifecycle`'s lock order).
pub fn combined_status(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let rev = ctx.param("sha").to_string();
    let mut resolved = None;
    let early = read_locked(ctx, &a, |ctx| match commit_of(ctx, &a, &rev) {
        Ok(s) => {
            resolved = Some(s);
            Resp::no_content()
        }
        Err(r) => r,
    });
    let Some(sha) = resolved else {
        return early;
    };
    let ctx: &Ctx = ctx;
    let all = match latest(ctx.conn, a.repo.id, &sha) {
        Ok(v) => v,
        Err(e) => return ctx.app.internal(&e),
    };
    let (page, limit) = page_params(ctx);
    let mut creators = HashMap::new();
    // Recorded (P#40-41): the page is cut from the newest end and then listed oldest first.
    let shown: Result<Vec<Value>, Resp> = all
        .iter()
        .rev()
        .skip(((page - 1) * limit) as usize)
        .take(limit as usize)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|s| status_json(ctx, &a, s, &mut creators))
        .collect();
    let shown = match shown {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Recorded: a commit with no statuses carries no repository object.
    let repo = if all.is_empty() {
        Value::Null
    } else {
        match repo_json(ctx.app, ctx.conn, &a.repo, a.perm) {
            Ok(v) => v,
            Err(r) => return r,
        }
    };
    let total = all.len() as i64;
    let body = json!({
        "state": combined_state(&all),
        "sha": sha,
        "total_count": shown.len(),
        "statuses": if shown.is_empty() { Value::Null } else { Value::Array(shown) },
        "repository": repo,
        "commit_url": "",
        "url": "",
    });
    let mut r = Resp::json(200, &body);
    if total > 0 {
        r = r.with("x-total-count", total.to_string());
    }
    let path = request_path(ctx);
    if let Some(l) = link_header(ctx, path, total, page, limit) {
        r = r.with("link", l);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(context: &str, state: &str) -> Status {
        Status {
            id: 0,
            sha: String::new(),
            context: context.into(),
            state: state.into(),
            description: String::new(),
            target_url: String::new(),
            creator_id: 1,
            created: 0,
            updated: 0,
        }
    }

    #[test]
    fn the_combined_state_follows_the_recorded_severity_order() {
        let c = |v: &[(&str, &str)]| {
            combined_state(&v.iter().map(|(c, st)| s(c, st)).collect::<Vec<_>>())
        };
        assert_eq!(c(&[]), "pending");
        assert_eq!(c(&[("a", "success")]), "success");
        assert_eq!(c(&[("a", "success"), ("b", "failure")]), "failure");
        assert_eq!(c(&[("a", "success"), ("b", "pending")]), "pending");
        assert_eq!(c(&[("a", "pending"), ("b", "error")]), "failure");
        assert_eq!(c(&[("a", "success"), ("b", "warning")]), "warning");
        assert_eq!(c(&[("a", "skipped")]), "skipped");
        assert_eq!(c(&[("a", "skipped"), ("b", "success")]), "success");
    }

    #[test]
    fn only_success_and_skipped_satisfy_a_required_context() {
        let l = [
            s("ci/test", "skipped"),
            s("ci/lint", "failure"),
            s("ci/x", "warning"),
        ];
        assert!(satisfied(&l, "ci/test"));
        assert!(!satisfied(&l, "ci/lint") && !satisfied(&l, "ci/x") && !satisfied(&l, "ci/none"));
    }

    #[test]
    fn urls_must_be_plain_http() {
        assert!(valid_url("") && valid_url("https://ci.example/run/1"));
        for bad in [
            "javascript:alert(1)",
            "ftp://x",
            "http://a b",
            "//x",
            "http://a\n",
        ] {
            assert!(!valid_url(bad), "{bad}");
        }
    }

    #[test]
    fn history_and_contexts_are_bounded() {
        let d = std::env::temp_dir().join(format!("scl-forge-status-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let conn = crate::db::open_for_admin(&d).unwrap();
        let owner = store::create_account(
            &conn,
            &store::NewAccount {
                login: "o".into(),
                visibility: "public".into(),
                ..Default::default()
            },
            1,
        )
        .unwrap();
        let repo = crate::repos::insert_creating(&conn, owner.id, "r", "main", "", "", 1).unwrap();
        let ins = |ctxt: &str, st: &str| {
            insert(&conn, repo.id, "abc", ctxt, st, "", "", owner.id, 5).unwrap()
        };
        for i in 0..MAX_HISTORY + 20 {
            assert!(matches!(
                ins("ci", if i % 2 == 0 { "success" } else { "failure" }),
                Inserted::Done(_)
            ));
        }
        assert_eq!(
            history(&conn, repo.id, "abc").unwrap().len() as i64,
            MAX_HISTORY
        );
        assert_eq!(latest(&conn, repo.id, "abc").unwrap().len(), 1);
        for i in 1..MAX_CONTEXTS {
            assert!(matches!(
                ins(&format!("c{i}"), "success"),
                Inserted::Done(_)
            ));
        }
        assert!(matches!(
            ins("one-too-many", "success"),
            Inserted::TooManyContexts
        ));
        assert!(
            matches!(ins("ci", "pending"), Inserted::Done(_)),
            "an existing context may still post"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
