//! The pull-request routes: create, list, get (with `.diff` and `.patch`), PATCH, commits, files and
//! the is-merged probe. The merge itself is F4c.
//!
//! Locking follows `lifecycle`'s order: writes take the repository's write gate (and with it the
//! shared lifecycle lock); reads take the shared lock once (`read_locked`). Nothing here calls
//! `repo_json` (it locks); the repository object is built with `repo_json_known`.

use crate::api::{body, page_params, paged_with, str_field, user_json};
use crate::content_api::{api_base, commit_json, dir, git_err, read_err, web_base, Users};
use crate::gitobj;
use crate::gitwrite as gw;
use crate::http::{error, not_found, Resp};
use crate::lifecycle::WriteRun;
use crate::pulls::{self, Pull, Sort};
use crate::refname;
use crate::repo_api::{acc, read_locked, repo_json_known};
use crate::repos::{Access, Perm};
use crate::routes::Ctx;
use crate::store;
use crate::timefmt::{now, rfc3339};
use serde_json::{json, Value};
use std::time::Duration;

const GATE_WAIT: Duration = Duration::from_secs(10);
const MAX_TITLE: usize = 255;
const MAX_BODY: usize = 65_536;
/// Changed files one `files` page may carry.
const MAX_FILES: usize = 3_000;

/// A repository path for a URL: every segment percent-encoded, the separators kept.
fn enc_path(p: &str) -> String {
    p.split('/')
        .map(crate::api::pct_encode)
        .collect::<Vec<_>>()
        .join("/")
}

fn missing(ctx: &Ctx) -> Resp {
    not_found(&ctx.app.base, "The target couldn't be found.", None)
}

fn needs_write(ctx: &Ctx) -> Resp {
    error(
        &ctx.app.base,
        403,
        "user should have a permission to write to a repo",
    )
}

/// The PR number out of a path parameter (`12`, or `12.diff` / `12.patch` where allowed).
fn number(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok().filter(|n| *n >= 1)
}

fn tip(ctx: &Ctx, a: &Access, branch: &str) -> Result<Option<String>, Resp> {
    if !refname::valid_branch(branch) {
        return Ok(None);
    }
    gw::read_ref(
        &ctx.app.life.git,
        &dir(ctx, a),
        &refname::branch_ref(branch),
    )
    .map_err(|e| read_err(ctx, a, e))
}

/// What the PR object shows now, as opposed to what is stored.
struct Live {
    base_sha: String,
    head_sha: String,
    head_ref: String,
    mergeable: bool,
    merge_base: Option<String>,
    changed_files: i64,
    additions: i64,
    deletions: i64,
}

/// The current facts of `p`: live tips while the branches exist, retained or frozen values after.
fn live(ctx: &Ctx, a: &Access, p: &Pull) -> Result<Live, Resp> {
    if p.state == "merged" {
        return Ok(Live {
            base_sha: p.merge_commit.clone().unwrap_or_else(|| p.base_sha.clone()),
            head_sha: p.final_head.clone().unwrap_or_else(|| p.head_sha.clone()),
            head_ref: p.head_ref.clone(),
            mergeable: false,
            merge_base: p.merge_base.clone(),
            changed_files: p.changed_files.unwrap_or(0),
            additions: p.additions.unwrap_or(0),
            deletions: p.deletions.unwrap_or(0),
        });
    }
    let base_sha = tip(ctx, a, &p.base_ref)?.unwrap_or_else(|| p.base_sha.clone());
    let kept = || -> Result<String, Resp> {
        let kept = gw::read_ref(
            &ctx.app.life.git,
            &dir(ctx, a),
            &pulls::retention_ref(p.number),
        )
        .map_err(|e| read_err(ctx, a, e))?;
        Ok(kept
            .or_else(|| p.final_head.clone())
            .unwrap_or_else(|| p.head_sha.clone()))
    };
    let branch = tip(ctx, a, &p.head_ref)?;
    let (head_sha, head_ref) = match (&p.state[..], branch) {
        // A closed PR keeps the head it was closed with, however its branch moves afterwards.
        ("closed", b) => (
            p.final_head.clone().map_or_else(kept, Ok)?,
            if b.is_some() {
                p.head_ref.clone()
            } else {
                format!("refs/pull/{}/head", p.number)
            },
        ),
        (_, Some(t)) => (t, p.head_ref.clone()),
        (_, None) => (kept()?, format!("refs/pull/{}/head", p.number)),
    };
    let c = pulls::compute(
        ctx.conn,
        &ctx.app.life.git,
        &dir(ctx, a),
        a.repo.id,
        &base_sha,
        &head_sha,
    )
    .map_err(|e| match e {
        pulls::ComputeError::Db(e) => ctx.app.internal(&e),
        pulls::ComputeError::Git(e) => read_err(ctx, a, e),
    })?;
    Ok(Live {
        base_sha,
        head_sha,
        head_ref,
        // Recorded: a closed PR keeps reading mergeable.
        mergeable: p.state != "open" || c.mergeable,
        merge_base: c.merge_base,
        changed_files: c.changed_files,
        additions: c.additions,
        deletions: c.deletions,
    })
}

fn pull_json(
    ctx: &Ctx,
    a: &Access,
    p: &Pull,
    l: &Live,
    repo: &Value,
    users: &mut std::collections::HashMap<i64, Value>,
) -> Result<Value, Resp> {
    let mut user = |id: i64| -> Result<Value, Resp> {
        if let Some(v) = users.get(&id) {
            return Ok(v.clone());
        }
        let u = store::find_by_id(ctx.conn, id)
            .map_err(|e| ctx.app.internal(&e))?
            .ok_or_else(|| ctx.app.internal(&"pull request without user"))?;
        let v = user_json(&ctx.app.base, &u);
        users.insert(id, v.clone());
        Ok(v)
    };
    let web = format!("{}/pulls/{}", web_base(ctx, a), p.number);
    let comments =
        pulls::comment_count(ctx.conn, a.repo.id, p.number).map_err(|e| ctx.app.internal(&e))?;
    let merged = p.state == "merged";
    Ok(json!({
        "id": p.id,
        "url": web,
        "number": p.number,
        "user": user(p.creator_id)?,
        "title": p.title,
        "body": p.body,
        "labels": [],
        "milestone": null,
        "assignee": null,
        "assignees": null,
        "requested_reviewers": null,
        "state": if p.state == "open" { "open" } else { "closed" },
        "draft": false,
        "is_locked": false,
        "comments": comments,
        "review_comments": 0,
        "additions": l.additions,
        "deletions": l.deletions,
        "changed_files": l.changed_files,
        "html_url": web,
        "diff_url": format!("{web}.diff"),
        "patch_url": format!("{web}.patch"),
        "mergeable": l.mergeable,
        "merged": merged,
        "merged_at": p.merged.filter(|_| merged).map(rfc3339),
        "merge_commit_sha": if merged { json!(p.merge_commit) } else { Value::Null },
        "merged_by": match p.merged_by.filter(|_| merged) { Some(id) => user(id)?, None => Value::Null },
        "allow_maintainer_edit": false,
        "base": {"label": p.base_ref, "ref": p.base_ref, "sha": l.base_sha, "repo_id": a.repo.id, "repo": repo},
        "head": {"label": p.head_ref, "ref": l.head_ref, "sha": l.head_sha, "repo_id": a.repo.id, "repo": repo},
        "merge_base": l.merge_base.clone().unwrap_or_default(),
        "due_date": null,
        "created_at": rfc3339(p.created),
        "updated_at": rfc3339(p.updated),
        "closed_at": p.closed.map(rfc3339),
        "pin_order": 0,
    }))
}

fn repo_value(ctx: &Ctx, a: &Access) -> Result<Value, Resp> {
    // A repository with a pull request has branches, so it is not empty; `repo_json` would take
    // the shared lifecycle lock a second time.
    repo_json_known(ctx.app, ctx.conn, &a.repo, a.perm, false)
}

fn render(ctx: &Ctx, a: &Access, p: &Pull) -> Result<Value, Resp> {
    let l = live(ctx, a, p)?;
    pull_json(ctx, a, p, &l, &repo_value(ctx, a)?, &mut Default::default())
}

/// The head commit a review or comment refers to now.
pub(crate) fn head_of(ctx: &Ctx, a: &Access, p: &Pull) -> Result<String, Resp> {
    live(ctx, a, p).map(|l| l.head_sha)
}

fn find(ctx: &Ctx, a: &Access, n: i64) -> Result<Pull, Resp> {
    match pulls::find(ctx.conn, a.repo.id, n) {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(missing(ctx)),
        Err(e) => Err(ctx.app.internal(&e)),
    }
}

/// Run `f` under the write gate.
fn gated(ctx: &Ctx, a: &Access, f: impl FnOnce() -> Resp) -> Resp {
    match ctx
        .app
        .life
        .with_write_row(ctx.conn, a.repo.id, GATE_WAIT, |_| f())
    {
        Ok(WriteRun::Ran(r)) => r,
        Ok(WriteRun::Busy) => error(
            &ctx.app.base,
            503,
            "this repository is being written to, try again",
        ),
        Ok(WriteRun::Gone) => missing(ctx),
        Err(e) => ctx.app.internal(&e),
    }
}

/// Before a read: if a push deleted the head of an open PR and its own sync has not run yet,
/// run it now (outside any lifecycle lock; the sync takes the write gate).
fn converge(ctx: &Ctx, a: &Access) {
    if pulls::has_vanished_head(ctx.conn, &ctx.app.life.git, &dir(ctx, a), a.repo.id) {
        pulls::sync(&ctx.app.life, ctx.conn, a.repo.id, now());
    }
}

/// Close the PRs whose head branch disappeared and refresh the retention refs, with the gate held.
pub(crate) fn sync_held(ctx: &Ctx, a: &Access) {
    if let Err(e) = pulls::sync_locked(ctx.conn, &ctx.app.life.git, &dir(ctx, a), a.repo.id, now())
    {
        eprintln!(
            "sc-forge: pull request sync of repository {} failed: {e}",
            a.repo.id
        );
    }
}

/// `owner:branch` or `branch` to the branch of this repository, or `None` for another repository.
fn local_branch(a: &Access, v: &str) -> Option<String> {
    match v.split_once(':') {
        Some((owner, branch)) => owner
            .eq_ignore_ascii_case(&a.repo.owner)
            .then(|| branch.to_string()),
        None => Some(v.to_string()),
    }
}

/// `POST /repos/{o}/{r}/pulls`.
pub fn create_pull(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    if a.perm < Perm::Write {
        return needs_write(ctx);
    }
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let title = str_field(&b, "title")
        .unwrap_or_default()
        .trim()
        .to_string();
    if title.is_empty() {
        return error(&ctx.app.base, 422, "[Title]: Required");
    }
    let text = str_field(&b, "body").unwrap_or_default();
    if title.chars().count() > MAX_TITLE || text.len() > MAX_BODY {
        return error(&ctx.app.base, 422, "[Title/Body]: too long");
    }
    let (Some(head), Some(base)) = (str_field(&b, "head"), str_field(&b, "base")) else {
        return error(&ctx.app.base, 422, "[Head/Base]: Required");
    };
    // Forks are not supported: a head in another repository does not exist here.
    let Some(head) = local_branch(&a, &head) else {
        return missing(ctx);
    };
    gated(ctx, &a, || {
        let Some(head_tip) = (match tip(ctx, &a, &head) {
            Ok(t) => t,
            Err(r) => return r,
        }) else {
            return missing(ctx);
        };
        let Some(base_tip) = (match tip(ctx, &a, &base) {
            Ok(t) => t,
            Err(r) => return r,
        }) else {
            return not_found(&ctx.app.base, "BaseNotExist", None);
        };
        match pulls::find_open(ctx.conn, a.repo.id, &head, &base) {
            Ok(Some(p)) => {
                return error(
                    &ctx.app.base,
                    409,
                    &format!(
                        "pull request already exists for these targets [id: {}, issue_id: {}, head_repo_id: {}, base_repo_id: {}, head_branch: {head}, base_branch: {base}]",
                        p.id, p.id, a.repo.id, a.repo.id
                    ),
                )
            }
            Ok(None) => {}
            Err(e) => return ctx.app.internal(&e),
        }
        if head_tip == base_tip {
            return error(
                &ctx.app.base,
                422,
                "Invalid PullRequest: There are no changes between the head and the base",
            );
        }
        let t = now();
        // The retention ref comes first: a crash leaves at worst an orphan ref (the startup
        // reconcile removes it), never a PR whose head could be pruned. Numbers are only handed
        // out under the write gate, so the next one is known.
        let number = match pulls::next_number(ctx.conn, a.repo.id) {
            Ok(n) => n,
            Err(e) => return ctx.app.internal(&e),
        };
        if let Err(e) = pulls::retain(&ctx.app.life.git, &dir(ctx, &a), number, &head_tip) {
            return read_err(ctx, &a, e);
        }
        let p = match pulls::insert(
            ctx.conn,
            a.repo.id,
            &head,
            &base,
            &base_tip,
            &head_tip,
            &title,
            &text,
            ctx.who.user.id,
            t,
        ) {
            Ok(p) => p,
            Err(e) => return ctx.app.internal(&e),
        };
        match render(ctx, &a, &p) {
            Ok(v) => Resp::json(201, &v),
            Err(r) => r,
        }
    })
}

/// `GET /repos/{o}/{r}/pulls`.
pub fn list_pulls(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    converge(ctx, &a);
    read_locked(ctx, &a, |ctx| list_inner(ctx, &a))
}

fn list_inner(ctx: &Ctx, a: &Access) -> Resp {
    // Recorded (D#13): Gitea answers 404 for the pull requests of a repository with no commits.
    match crate::gitread::is_empty(&ctx.app.life.git, &dir(ctx, a)) {
        Ok(true) => return missing(ctx),
        Ok(false) => {}
        Err(e) => return read_err(ctx, a, e),
    }
    let (state, sort) = (ctx.req.param("state"), ctx.req.param("sort"));
    let states: &[&str] = match state {
        None | Some("open") | Some("") => &["open"],
        Some("closed") => &["closed", "merged"],
        Some("all") => &["open", "closed", "merged"],
        Some(_) => &["open"],
    };
    let order = match sort {
        Some("oldest") => Sort::Oldest,
        Some("recentupdate") => Sort::RecentUpdate,
        _ => Sort::Newest,
    };
    let (page, limit) = page_params(ctx);
    let (rows, total) = match pulls::list(
        ctx.conn,
        a.repo.id,
        states,
        order,
        (page - 1) * limit,
        limit,
    ) {
        Ok(x) => x,
        Err(e) => return ctx.app.internal(&e),
    };
    let repo = match repo_value(ctx, a) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut users = Default::default();
    let mut items = Vec::with_capacity(rows.len());
    for p in &rows {
        let l = match live(ctx, a, p) {
            Ok(l) => l,
            Err(r) => return r,
        };
        match pull_json(ctx, a, p, &l, &repo, &mut users) {
            Ok(v) => items.push(v),
            Err(r) => return r,
        }
    }
    paged_with(
        ctx,
        &format!("/repos/{}/{}/pulls", a.repo.owner, a.repo.name),
        total,
        page,
        limit,
        items,
    )
}

fn text_response(body: Vec<u8>) -> Resp {
    Resp {
        status: 200,
        headers: vec![("content-type", "text/plain;charset=utf-8".into())],
        body,
        delay: Duration::ZERO,
        hold: None,
    }
}

/// `GET /repos/{o}/{r}/pulls/{n}` and its `.diff` / `.patch` forms.
pub fn get_pull(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let raw = ctx.param("n").to_string();
    let (num, ext) = match raw.rsplit_once('.') {
        Some((n, e)) if matches!(e, "diff" | "patch") => (n.to_string(), Some(e.to_string())),
        _ => (raw, None),
    };
    let Some(n) = number(&num) else {
        return missing(ctx);
    };
    converge(ctx, &a);
    read_locked(ctx, &a, |ctx| {
        let p = match find(ctx, &a, n) {
            Ok(p) => p,
            Err(r) => return r,
        };
        match ext.as_deref() {
            None => match render(ctx, &a, &p) {
                Ok(v) => Resp::json(200, &v),
                Err(r) => r,
            },
            Some(e) => {
                let l = match live(ctx, &a, &p) {
                    Ok(l) => l,
                    Err(r) => return r,
                };
                let (git, d) = (&ctx.app.life.git, dir(ctx, &a));
                let out = if e == "diff" {
                    gitobj::diff_text(git, &d, l.merge_base.as_deref(), &l.head_sha)
                } else {
                    gitobj::range_patch(git, &d, l.merge_base.as_deref(), &l.head_sha)
                };
                match git_err(ctx, &a, out) {
                    Ok(bytes) => text_response(bytes),
                    Err(r) => r,
                }
            }
        }
    })
}

/// `PATCH /repos/{o}/{r}/pulls/{n}`: title, body, state, base. Answers 201 (recorded).
pub fn patch_pull(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let Some(n) = number(ctx.param("n")) else {
        return missing(ctx);
    };
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    gated(ctx, &a, || {
        let mut p = match find(ctx, &a, n) {
            Ok(p) => p,
            Err(r) => return r,
        };
        if a.perm < Perm::Write && p.creator_id != ctx.who.user.id {
            return needs_write(ctx);
        }
        if let Some(t) = str_field(&b, "title") {
            let t = t.trim().to_string();
            if t.is_empty() || t.chars().count() > MAX_TITLE {
                return error(
                    &ctx.app.base,
                    422,
                    "[Title]: Required, at most 255 characters",
                );
            }
            p.title = t;
        }
        if let Some(t) = str_field(&b, "body") {
            if t.len() > MAX_BODY {
                return error(&ctx.app.base, 422, "[Body]: too long");
            }
            p.body = t;
        }
        if let Some(new_base) = str_field(&b, "base").filter(|s| !s.is_empty()) {
            if p.state == "merged" {
                return error(&ctx.app.base, 422, "the pull request is already merged");
            }
            if new_base != p.base_ref {
                let Some(t) = (match tip(ctx, &a, &new_base) {
                    Ok(t) => t,
                    Err(r) => return r,
                }) else {
                    return not_found(&ctx.app.base, "BaseNotExist", None);
                };
                if new_base == p.head_ref {
                    return error(&ctx.app.base, 422, "the base cannot be the head branch");
                }
                if p.state == "open"
                    && matches!(
                        pulls::find_open(ctx.conn, a.repo.id, &p.head_ref, &new_base),
                        Ok(Some(_))
                    )
                {
                    return error(
                        &ctx.app.base,
                        409,
                        "pull request already exists for these targets",
                    );
                }
                p.base_ref = new_base;
                p.base_sha = t;
            }
        }
        let t = now();
        match str_field(&b, "state").as_deref() {
            None | Some("") => {}
            Some("closed") if p.state == "open" => {
                let head = match tip(ctx, &a, &p.head_ref) {
                    Ok(Some(h)) => h,
                    Ok(None) => gw::read_ref(
                        &ctx.app.life.git,
                        &dir(ctx, &a),
                        &pulls::retention_ref(p.number),
                    )
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| p.head_sha.clone()),
                    Err(r) => return r,
                };
                if let Err(e) = pulls::retain(&ctx.app.life.git, &dir(ctx, &a), p.number, &head) {
                    return read_err(ctx, &a, e);
                }
                p.head_sha = head.clone();
                p.final_head = Some(head);
                p.state = "closed".into();
                p.closed = Some(t);
            }
            Some("open") if p.state == "closed" => {
                match pulls::find_open(ctx.conn, a.repo.id, &p.head_ref, &p.base_ref) {
                    Ok(None) => {}
                    Ok(Some(_)) => {
                        return error(
                            &ctx.app.base,
                            409,
                            "pull request already exists for these targets",
                        )
                    }
                    Err(e) => return ctx.app.internal(&e),
                }
                // Recorded: reopening works even when the head branch is gone.
                p.head_gone = !matches!(tip(ctx, &a, &p.head_ref), Ok(Some(_)));
                p.state = "open".into();
                p.closed = None;
                p.final_head = None;
            }
            Some("open") | Some("closed") if p.state == "merged" => {
                return error(&ctx.app.base, 422, "the pull request is already merged")
            }
            Some("open") | Some("closed") => {}
            Some(_) => return error(&ctx.app.base, 422, "[State]: must be open or closed"),
        }
        p.updated = t;
        if let Err(e) = pulls::save(ctx.conn, &p) {
            return match e {
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    error(
                        &ctx.app.base,
                        409,
                        "pull request already exists for these targets",
                    )
                }
                e => ctx.app.internal(&e),
            };
        }
        // A reopened PR follows its branch again: bring its retention ref along (gate held).
        sync_held(ctx, &a);
        let p = match find(ctx, &a, n) {
            Ok(p) => p,
            Err(r) => return r,
        };
        match render(ctx, &a, &p) {
            Ok(v) => Resp::json(201, &v),
            Err(r) => r,
        }
    })
}

/// `GET /repos/{o}/{r}/pulls/{n}/merge`: 204 once merged, 404 otherwise.
pub fn is_merged(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let Some(n) = number(ctx.param("n")) else {
        return missing(ctx);
    };
    match find(ctx, &a, n) {
        Ok(p) if p.state == "merged" => Resp::no_content(),
        Ok(_) => missing(ctx),
        Err(r) => r,
    }
}

/// `GET /repos/{o}/{r}/pulls/{n}/commits`: `merge_base..head`, newest first, with files and stats.
pub fn pull_commits(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let Some(n) = number(ctx.param("n")) else {
        return missing(ctx);
    };
    converge(ctx, &a);
    read_locked(ctx, &a, |ctx| {
        let p = match find(ctx, &a, n) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let l = match live(ctx, &a, &p) {
            Ok(l) => l,
            Err(r) => return r,
        };
        let (git, d) = (&ctx.app.life.git, dir(ctx, &a));
        let (page, limit) = page_params(ctx);
        let mb = l.merge_base.as_deref();
        let total = match git_err(ctx, &a, gitobj::range_count(git, &d, mb, &l.head_sha)) {
            Ok(t) => t as i64,
            Err(r) => return r,
        };
        let commits = match git_err(
            ctx,
            &a,
            gitobj::range_log(
                git,
                &d,
                mb,
                &l.head_sha,
                ((page - 1) * limit) as usize,
                limit as usize,
            ),
        ) {
            Ok(c) => c,
            Err(r) => return r,
        };
        let mut users = Users::new(ctx);
        let mut items = Vec::new();
        // The per-command output cap does not bound a page of up to 50 commits that each list a huge
        // change set, so the files kept for one response are bounded as a whole.
        let mut files_left = crate::content_api::MAX_PAGE_FILES;
        for c in &commits {
            let (files, stats) = match git_err(
                ctx,
                &a,
                gitobj::changes(git, &d, c.parents.first().map(String::as_str), &c.oid),
            ) {
                Ok(x) => x,
                Err(r) => return r,
            };
            if files.len() > files_left {
                return error(
                    &ctx.app.base,
                    413,
                    "the changed files of this page are too many",
                );
            }
            files_left -= files.len();
            match commit_json(
                ctx,
                &a,
                &mut users,
                c,
                true,
                Some((Some(files), Some(stats))),
            ) {
                Ok(v) => items.push(v),
                Err(r) => return r,
            }
        }
        paged_with(
            ctx,
            &format!("/repos/{}/{}/pulls/{n}/commits", a.repo.owner, a.repo.name),
            total,
            page,
            limit,
            items,
        )
    })
}

/// `GET /repos/{o}/{r}/pulls/{n}/files`: the files `merge_base...head` changes.
pub fn pull_files(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let Some(n) = number(ctx.param("n")) else {
        return missing(ctx);
    };
    converge(ctx, &a);
    read_locked(ctx, &a, |ctx| {
        let p = match find(ctx, &a, n) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let l = match live(ctx, &a, &p) {
            Ok(l) => l,
            Err(r) => return r,
        };
        let all = match git_err(
            ctx,
            &a,
            gitobj::file_stats(
                &ctx.app.life.git,
                &dir(ctx, &a),
                l.merge_base.as_deref(),
                &l.head_sha,
            ),
        ) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let (page, limit) = page_params(ctx);
        let (api, web) = (api_base(ctx, &a), web_base(ctx, &a));
        let items: Vec<Value> = all
            .iter()
            .skip(((page - 1) * limit) as usize)
            .take((limit as usize).min(MAX_FILES))
            .map(|f| {
                json!({
                    "filename": f.name,
                    "status": f.status,
                    "additions": f.additions,
                    "deletions": f.deletions,
                    "changes": f.additions + f.deletions,
                    "html_url": format!("{web}/src/commit/{}/{}", l.head_sha, enc_path(&f.name)),
                    "contents_url": format!("{api}/contents/{}?ref={}", enc_path(&f.name), l.head_sha),
                    "raw_url": format!("{web}/raw/commit/{}/{}", l.head_sha, enc_path(&f.name)),
                })
            })
            .collect();
        paged_with(
            ctx,
            &format!("/repos/{}/{}/pulls/{n}/files", a.repo.owner, a.repo.name),
            all.len() as i64,
            page,
            limit,
            items,
        )
    })
}
