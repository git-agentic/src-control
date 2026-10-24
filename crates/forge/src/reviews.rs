//! Reviews of a pull request and issue comments (an issue number is the PR number).
//!
//! Recorded Gitea behaviour kept: an unknown review `event` is stored as `PENDING`; approving or
//! requesting changes on your own PR is 422; a reviewer without write access can approve but the
//! review is not `official`; a reviewer's later approval or change request dismisses their
//! earlier ones; a `PENDING` review is visible only to its author, yet still counted in
//! `X-Total-Count`. Inline review comments are not supported (a non-empty `comments` is 422, never
//! silently dropped), so a review's comment list is always empty.

use crate::api::{body, nested_user_json, page_params, paged, str_field, user_json};
use crate::content_api::web_base;
use crate::http::{error, not_found, Resp};
use crate::pulls;
use crate::repo_api::acc;
use crate::repos::{Access, Perm};
use crate::routes::Ctx;
use crate::store;
use crate::timefmt::{now, rfc3339};
use rusqlite::{params, Connection};
use serde_json::{json, Value};

const MAX_TEXT: usize = 65_536;
/// Reviews per PR and comments per PR; a bound on what one repository can pile up.
const MAX_REVIEWS: i64 = 1_000;
const MAX_COMMENTS: i64 = 5_000;

struct Review {
    id: i64,
    reviewer: i64,
    state: String,
    body: String,
    commit_id: String,
    official: bool,
    created: i64,
}

fn missing(ctx: &Ctx) -> Resp {
    not_found(&ctx.app.base, "The target couldn't be found.", None)
}

fn number(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok().filter(|n| *n >= 1)
}

fn all_reviews(conn: &Connection, repo_id: i64, n: i64) -> rusqlite::Result<Vec<Review>> {
    let mut st = conn.prepare(
        "SELECT id, reviewer_id, state, body, commit_id, official, created_unix FROM reviews \
         WHERE repo_id = ?1 AND pull_number = ?2 ORDER BY id",
    )?;
    let rows = st
        .query_map(params![repo_id, n], |r| {
            Ok(Review {
                id: r.get(0)?,
                reviewer: r.get(1)?,
                state: r.get(2)?,
                body: r.get(3)?,
                commit_id: r.get(4)?,
                official: r.get::<_, i64>(5)? != 0,
                created: r.get(6)?,
            })
        })?
        .collect();
    rows
}

fn decides(state: &str) -> bool {
    matches!(state, "APPROVED" | "REQUEST_CHANGES")
}

/// `created` is the POST answer, which (recorded) shows the full account; later reads show the nested form.
fn review_json(
    ctx: &Ctx,
    a: &Access,
    n: i64,
    r: &Review,
    all: &[Review],
    created: bool,
) -> Result<Value, Resp> {
    let u = store::find_by_id(ctx.conn, r.reviewer)
        .map_err(|e| ctx.app.internal(&e))?
        .ok_or_else(|| ctx.app.internal(&"review without reviewer"))?;
    // Superseded by a later decision of the same reviewer.
    let dismissed = decides(&r.state)
        && all
            .iter()
            .any(|o| o.id > r.id && o.reviewer == r.reviewer && decides(&o.state));
    let web = format!("{}/pulls/{n}", web_base(ctx, a));
    Ok(json!({
        "id": r.id,
        "user": if created { user_json(&ctx.app.base, &u) } else { nested_user_json(&ctx.app.base, &u, false) },
        "team": null,
        "state": r.state,
        "body": r.body,
        "commit_id": r.commit_id,
        "stale": false,
        "official": r.official && !dismissed,
        "dismissed": dismissed,
        "comments_count": 0,
        "submitted_at": rfc3339(r.created),
        "updated_at": rfc3339(r.created),
        "html_url": format!("{web}#issuecomment-{}", r.id),
        "pull_request_url": web,
    }))
}

fn pull_of(ctx: &Ctx, a: &Access, n: i64) -> Result<pulls::Pull, Resp> {
    match pulls::find(ctx.conn, a.repo.id, n) {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(missing(ctx)),
        Err(e) => Err(ctx.app.internal(&e)),
    }
}

/// A review the caller may see: not somebody else's `PENDING` one.
fn visible(ctx: &Ctx, r: &Review) -> bool {
    r.state != "PENDING" || r.reviewer == ctx.who.user.id
}

/// `GET /repos/{o}/{r}/pulls/{n}/reviews`.
pub fn list_reviews(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let Some(n) = number(ctx.param("n")) else {
        return missing(ctx);
    };
    if let Err(r) = pull_of(ctx, &a, n) {
        return r;
    }
    let all = match all_reviews(ctx.conn, a.repo.id, n) {
        Ok(v) => v,
        Err(e) => return ctx.app.internal(&e),
    };
    let (page, limit) = page_params(ctx);
    let mut items = Vec::new();
    for r in all
        .iter()
        .filter(|r| visible(ctx, r))
        .skip(((page - 1) * limit) as usize)
        .take(limit as usize)
    {
        match review_json(ctx, &a, n, r, &all, false) {
            Ok(v) => items.push(v),
            Err(r) => return r,
        }
    }
    // Recorded quirk: the total counts reviews the caller cannot see.
    paged(
        ctx,
        &format!("/repos/{}/{}/pulls/{n}/reviews", a.repo.owner, a.repo.name),
        all.len() as i64,
        page,
        limit,
        items,
    )
}

/// The review the path names (and all the PR's reviews, which dismissal needs), if the caller may see it.
fn one(ctx: &Ctx, a: &Access) -> Result<(i64, usize, Vec<Review>), Resp> {
    let (Some(n), Some(id)) = (number(ctx.param("n")), number(ctx.param("id"))) else {
        return Err(missing(ctx));
    };
    pull_of(ctx, a, n)?;
    let all = all_reviews(ctx.conn, a.repo.id, n).map_err(|e| ctx.app.internal(&e))?;
    match all.iter().position(|r| r.id == id) {
        Some(pos) if visible(ctx, &all[pos]) => Ok((n, pos, all)),
        _ => Err(missing(ctx)),
    }
}

/// `GET /repos/{o}/{r}/pulls/{n}/reviews/{id}`.
pub fn get_review(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    match one(ctx, &a).and_then(|(n, pos, all)| review_json(ctx, &a, n, &all[pos], &all, false)) {
        Ok(v) => Resp::json(200, &v),
        Err(r) => r,
    }
}

/// `GET /repos/{o}/{r}/pulls/{n}/reviews/{id}/comments`: always empty (no inline comments).
pub fn review_comments(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    match one(ctx, &a) {
        Ok(_) => Resp::json(200, &json!([])),
        Err(r) => r,
    }
}

/// `POST /repos/{o}/{r}/pulls/{n}/reviews`.
pub fn create_review(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let Some(n) = number(ctx.param("n")) else {
        return missing(ctx);
    };
    let p = match pull_of(ctx, &a, n) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    if b.get("comments")
        .is_some_and(|c| c.as_array().is_none_or(|a| !a.is_empty()) && !c.is_null())
    {
        return error(
            &ctx.app.base,
            422,
            "inline review comments are not supported",
        );
    }
    let text = str_field(&b, "body").unwrap_or_default();
    if text.len() > MAX_TEXT {
        return error(&ctx.app.base, 422, "[Body]: too long");
    }
    // Anything but the three known events is a pending review (recorded).
    let state = match str_field(&b, "event")
        .unwrap_or_default()
        .to_uppercase()
        .as_str()
    {
        "APPROVED" | "APPROVE" => "APPROVED",
        "REQUEST_CHANGES" => "REQUEST_CHANGES",
        "COMMENT" => "COMMENT",
        _ => "PENDING",
    };
    let me = ctx.who.user.id;
    if p.creator_id == me && decides(state) {
        return error(
            &ctx.app.base,
            422,
            if state == "APPROVED" {
                "approve your own pull is not allowed"
            } else {
                "reject your own pull is not allowed"
            },
        );
    }
    match all_reviews(ctx.conn, a.repo.id, n) {
        Ok(v) if v.len() as i64 >= MAX_REVIEWS => {
            return error(&ctx.app.base, 422, "this pull request has too many reviews")
        }
        Ok(_) => {}
        Err(e) => return ctx.app.internal(&e),
    }
    // Git runs under the shared lifecycle lock, so a delete in flight answers 404, not a git error.
    let commit_id = match ctx.app.life.with_read(ctx.conn, a.repo.id, || {
        crate::pulls_api::head_of(ctx, &a, &p)
    }) {
        Ok(Some(Ok(h))) => h,
        Ok(Some(Err(r))) => return r,
        Ok(None) => return missing(ctx),
        Err(e) => return ctx.app.internal(&e),
    };
    let official = a.perm >= Perm::Write && decides(state);
    let t = now();
    if let Err(e) = ctx.conn.execute(
        "INSERT INTO reviews (repo_id, pull_number, reviewer_id, state, body, commit_id, official, created_unix) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![a.repo.id, n, me, state, text, commit_id, official, t],
    ) {
        return ctx.app.internal(&e);
    }
    let id = ctx.conn.last_insert_rowid();
    let all = match all_reviews(ctx.conn, a.repo.id, n) {
        Ok(v) => v,
        Err(e) => return ctx.app.internal(&e),
    };
    let Some(r) = all.iter().find(|r| r.id == id) else {
        return ctx.app.internal(&"review vanished");
    };
    match review_json(ctx, &a, n, r, &all, true) {
        Ok(v) => Resp::json(200, &v),
        Err(r) => r,
    }
}

// ---- issue comments ----

fn comment_json(
    ctx: &Ctx,
    a: &Access,
    n: i64,
    id: i64,
    author: i64,
    text: &str,
    created: i64,
    updated: i64,
) -> Result<Value, Resp> {
    let u = store::find_by_id(ctx.conn, author)
        .map_err(|e| ctx.app.internal(&e))?
        .ok_or_else(|| ctx.app.internal(&"comment without author"))?;
    let web = format!("{}/pulls/{n}", web_base(ctx, a));
    Ok(json!({
        "id": id,
        "html_url": format!("{web}#issuecomment-{id}"),
        "pull_request_url": web,
        "issue_url": "",
        "user": nested_user_json(&ctx.app.base, &u, true),
        "original_author": "",
        "original_author_id": 0,
        "body": text,
        "assets": [],
        "created_at": rfc3339(created),
        "updated_at": rfc3339(updated),
    }))
}

/// `GET /repos/{o}/{r}/issues/{n}/comments`: oldest first.
pub fn list_comments(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let Some(n) = number(ctx.param("n")) else {
        return missing(ctx);
    };
    if let Err(r) = pull_of(ctx, &a, n) {
        return r;
    }
    let (page, limit) = page_params(ctx);
    let total = match pulls::comment_count(ctx.conn, a.repo.id, n) {
        Ok(t) => t,
        Err(e) => return ctx.app.internal(&e),
    };
    type Row = (i64, i64, String, i64, i64);
    let rows: Result<Vec<Row>, _> = ctx
        .conn
        .prepare(
            "SELECT id, author_id, body, created_unix, updated_unix FROM issue_comments \
             WHERE repo_id = ?1 AND number = ?2 ORDER BY id LIMIT ?3 OFFSET ?4",
        )
        .and_then(|mut s| {
            s.query_map(params![a.repo.id, n, limit, (page - 1) * limit], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect()
        });
    let rows = match rows {
        Ok(r) => r,
        Err(e) => return ctx.app.internal(&e),
    };
    let mut items = Vec::new();
    for (id, author, text, c, u) in rows {
        match comment_json(ctx, &a, n, id, author, &text, c, u) {
            Ok(v) => items.push(v),
            Err(r) => return r,
        }
    }
    paged(
        ctx,
        &format!(
            "/repos/{}/{}/issues/{n}/comments",
            a.repo.owner, a.repo.name
        ),
        total,
        page,
        limit,
        items,
    )
}

/// `POST /repos/{o}/{r}/issues/{n}/comments`.
pub fn create_comment(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let Some(n) = number(ctx.param("n")) else {
        return missing(ctx);
    };
    if let Err(r) = pull_of(ctx, &a, n) {
        return r;
    }
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let text = str_field(&b, "body").unwrap_or_default();
    if text.trim().is_empty() {
        return error(&ctx.app.base, 422, "[Body]: Required");
    }
    if text.len() > MAX_TEXT {
        return error(&ctx.app.base, 422, "[Body]: too long");
    }
    match pulls::comment_count(ctx.conn, a.repo.id, n) {
        Ok(c) if c >= MAX_COMMENTS => {
            return error(
                &ctx.app.base,
                422,
                "this pull request has too many comments",
            )
        }
        Ok(_) => {}
        Err(e) => return ctx.app.internal(&e),
    }
    let t = now();
    if let Err(e) = ctx.conn.execute(
        "INSERT INTO issue_comments (repo_id, number, author_id, body, created_unix, updated_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![a.repo.id, n, ctx.who.user.id, text, t],
    ) {
        return ctx.app.internal(&e);
    }
    let id = ctx.conn.last_insert_rowid();
    match comment_json(ctx, &a, n, id, ctx.who.user.id, &text, t, t) {
        Ok(v) => Resp::json(201, &v),
        Err(r) => r,
    }
}
