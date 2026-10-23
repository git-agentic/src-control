//! F2a handlers: repositories, search and lists, collaborators, branches. Authentication, scope
//! and the repository permission check already passed in `routes::dispatch` (`ctx.access`).

use crate::api::{body, page_params, paged, paged_with, str_field, user_json};
use crate::gitproc::GitError;
use crate::gitread;
use crate::http::{error, not_found, Resp};
use crate::lifecycle::LifecycleError;
use crate::names::{self, RepoNameError};
use crate::refname;
use crate::repos::{self, Access, Filter, Perm, Repo, RepoPatch, Sort};
use crate::routes::{App, Ctx};
use crate::scope;
use crate::store::{self, User};
use crate::timefmt::{now, rfc3339};
use serde_json::{json, Value};

fn acc<'a>(ctx: &'a Ctx) -> Result<&'a Access, Resp> {
    ctx.access.as_ref().ok_or_else(|| {
        ctx.app
            .internal(&"repository route without a resolved repository")
    })
}

fn life_err(app: &App, e: LifecycleError) -> Resp {
    match e {
        LifecycleError::Exists => error(
            &app.base,
            409,
            "The repository with the same name already exists.",
        ),
        LifecycleError::BadBranch => error(&app.base, 422, "[DefaultBranch]: invalid branch name"),
        LifecycleError::Gone => not_found(&app.base, "The target couldn't be found.", None),
        LifecycleError::Git(crate::gitproc::GitError::Busy) => {
            error(&app.base, 503, "too many git operations in flight")
        }
        other => app.internal(&other),
    }
}

/// The one mapping of a failed read of a repository: busy is 503; a repository that is no
/// longer `live` (a read that raced its delete) is the same 404 as a missing one; anything else
/// is a 500.
fn git_read_err(app: &App, conn: &rusqlite::Connection, repo_id: i64, e: GitError) -> Resp {
    if matches!(e, GitError::Busy) {
        return error(&app.base, 503, "too many git operations in flight");
    }
    match repos::find_by_id(conn, repo_id) {
        Ok(Some(r)) if r.state == "live" => app.internal(&e),
        _ => not_found(&app.base, "The target couldn't be found.", None),
    }
}

fn ssh_authority(base: &str) -> String {
    base.split("://")
        .nth(1)
        .unwrap_or(base)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

/// The ~70-key repository object recorded from Gitea. `perm` is the *caller's* standing.
fn repo_json(app: &App, conn: &rusqlite::Connection, r: &Repo, perm: Perm) -> Result<Value, Resp> {
    let owner = store::find_by_id(conn, r.owner_id)
        .map_err(|e| app.internal(&e))?
        .ok_or_else(|| app.internal(&"repo without owner"))?;
    // Under the shared repository lock, and only while the repository is still live: a read must
    // never straddle a delete's rename and see a half-vanished repository as an empty one.
    let empty = match app.life.with_read(conn, r.id, || {
        gitread::is_empty(&app.life.git, &app.life.repo_dir(r.id))
    }) {
        Err(e) => return Err(app.internal(&e)),
        Ok(None) => return Err(not_found(&app.base, "The target couldn't be found.", None)),
        Ok(Some(res)) => res.map_err(|e| git_read_err(app, conn, r.id, e))?,
    };
    let mut owner_json = user_json(&app.base, &owner);
    owner_json["active"] = json!(false); // recorded: the owner object inside a repository reads inactive
    owner_json["login_name"] = json!(""); // recorded: the nested owner never carries the login_name
    owner_json["is_admin"] = json!(false); // recorded: nor does it ever read as a site admin
    let (b, full) = (&app.base, format!("{}/{}", r.owner, r.name));
    Ok(json!({
        "id": r.id,
        "owner": owner_json,
        "name": r.name,
        "full_name": full,
        "description": r.description,
        "empty": empty,
        "private": true,
        "fork": false,
        "template": false,
        "parent": null,
        "mirror": false,
        "size": 0,
        "language": "",
        "languages_url": format!("{b}/api/v1/repos/{full}/languages"),
        "html_url": format!("{b}/{full}"),
        "url": format!("{b}/api/v1/repos/{full}"),
        "link": "",
        "ssh_url": format!("ssh://{}/{full}.git", ssh_authority(b)),
        "clone_url": format!("{b}/{full}.git"),
        "original_url": "",
        "website": r.website,
        "stars_count": 0,
        "forks_count": 0,
        "watchers_count": 1,
        "open_issues_count": 0,
        "open_pr_counter": 0,
        "release_counter": 0,
        "default_branch": r.default_branch,
        "archived": false,
        "created_at": rfc3339(r.created),
        "updated_at": rfc3339(r.updated),
        "archived_at": "1970-01-01T00:00:00Z",
        "permissions": {"admin": perm >= Perm::Admin, "push": perm >= Perm::Write, "pull": true},
        "has_issues": true,
        "internal_tracker": {"enable_time_tracker": true, "allow_only_contributors_to_track_time": true, "enable_issue_dependencies": true},
        "has_wiki": true,
        "has_pull_requests": true,
        "has_projects": true,
        "projects_mode": "all",
        "has_releases": true,
        "has_packages": true,
        "has_actions": false,
        "ignore_whitespace_conflicts": false,
        "allow_merge_commits": true,
        "allow_rebase": true,
        "allow_rebase_explicit": true,
        "allow_squash_merge": true,
        "allow_fast_forward_only_merge": true,
        "allow_rebase_update": true,
        "default_delete_branch_after_merge": false,
        "default_merge_style": "merge",
        "default_allow_maintainer_edit": false,
        "avatar_url": "",
        "internal": false,
        "mirror_interval": "",
        "object_format_name": "sha1",
        "mirror_updated": "1970-01-01T00:00:00Z",
        "repo_transfer": null,
    }))
}

/// A listed repository with the caller's standing computed per row.
fn listed(ctx: &Ctx, rows: &[Repo]) -> Result<Vec<Value>, Resp> {
    rows.iter()
        .map(|r| {
            let perm = repos::resolve(ctx.conn, &ctx.who.user, &r.owner, &r.name)
                .map_err(|e| ctx.app.internal(&e))?
                .map_or(Perm::Read, |a| a.perm);
            repo_json(ctx.app, ctx.conn, r, perm)
        })
        .collect()
}

fn token_public_only(ctx: &Ctx) -> bool {
    ctx.who.scopes.as_deref().is_some_and(scope::public_only)
}

fn name_error(e: RepoNameError, name: &str) -> String {
    match e {
        RepoNameError::Empty => "[Name]: Required".into(),
        RepoNameError::Reserved => format!("name is reserved [name: {name}]"),
        RepoNameError::Pattern(p) => format!("name pattern is not allowed [pattern: {p}]"),
        RepoNameError::BadChars => "[Name]: AlphaDashDot".into(),
        RepoNameError::TooLong => "[Name]: MaxSize".into(),
    }
}

/// Create a repository owned by `owner` for the caller (shared by the org and user routes).
fn create_for(ctx: &mut Ctx, owner: &User) -> Resp {
    // Every repository is private, so a token restricted to public repositories may not create
    // one; refused before the name or any existence is looked at (as `resolve_repo` does).
    if token_public_only(ctx) {
        return error(&ctx.app.base, 403, "token scope is limited to public repos");
    }
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let base = ctx.app.base.clone();
    let name = str_field(&b, "name").unwrap_or_default();
    if let Err(e) = names::check_repo(&name) {
        return error(&base, 422, &name_error(e, &name));
    }
    let branch = str_field(&b, "default_branch")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "main".into());
    if !refname::valid_branch(&branch) {
        return error(&base, 422, "[DefaultBranch]: invalid branch name");
    }
    // `private` is accepted and ignored: every repository is private (recorded Gitea forces it
    // on create; an anonymous-read hole on PATCH is not copied).
    let auto_init = b.get("auto_init").and_then(Value::as_bool).unwrap_or(false);
    let description = str_field(&b, "description").unwrap_or_default();
    let created = ctx.app.life.create(
        ctx.conn,
        owner,
        &ctx.who.user,
        &name,
        &description,
        &branch,
        auto_init,
        now(),
    );
    match created {
        Ok(r) => match repo_json(ctx.app, ctx.conn, &r, Perm::Admin) {
            Ok(v) => Resp::json(201, &v),
            Err(resp) => resp,
        },
        Err(e) => life_err(ctx.app, e),
    }
}

/// `POST /orgs/{o}/repos`: the actor check already required an owner of `{o}` or a site admin.
pub fn create_org_repo(ctx: &mut Ctx) -> Resp {
    let name = ctx.param("o").to_string();
    match store::find_by_login(ctx.conn, &name) {
        Ok(Some(org)) if org.is_org => create_for(ctx, &org),
        Ok(_) => crate::api::org_missing(ctx.app, &name),
        Err(e) => ctx.app.internal(&e),
    }
}

/// `POST /user/repos`: the caller owns the new repository.
pub fn create_user_repo(ctx: &mut Ctx) -> Resp {
    let me = ctx.who.user.clone();
    create_for(ctx, &me)
}

/// `GET /repos/{o}/{r}`.
pub fn get_repo(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a,
        Err(r) => return r,
    };
    match repo_json(ctx.app, ctx.conn, &a.repo, a.perm) {
        Ok(v) => Resp::json(200, &v),
        Err(r) => r,
    }
}

/// `PATCH /repos/{o}/{r}`: description, website and default branch; rename is refused; the
/// other Gitea fields (`private`, `has_*`, `allow_*`, ...) are accepted and ignored.
pub fn patch_repo(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let base = ctx.app.base.clone();
    if str_field(&b, "name").is_some_and(|n| n != a.repo.name) {
        return error(&base, 422, "repository rename is not supported");
    }
    // Always handed to the locked operation, which compares against the row under the lock (a
    // snapshot taken before the lock could be stale).
    if let Some(branch) = str_field(&b, "default_branch") {
        if !refname::valid_branch(&branch) {
            return error(&base, 422, "[DefaultBranch]: invalid branch name");
        }
        match ctx
            .app
            .life
            .set_default_branch(ctx.conn, &a.repo, &branch, now())
        {
            Ok(()) => {}
            Err(LifecycleError::NoSuchBranch) => {
                return error(
                    &base,
                    422,
                    &format!("branch does not exist [name: {branch}]"),
                )
            }
            Err(e) => return life_err(ctx.app, e),
        }
    }
    let patch = RepoPatch {
        description: str_field(&b, "description"),
        website: str_field(&b, "website"),
        default_branch: None,
    };
    match repos::update_live(ctx.conn, a.repo.id, &patch, now()) {
        Ok(true) => {}
        Ok(false) => return not_found(&base, "The target couldn't be found.", None),
        Err(e) => return ctx.app.internal(&e),
    }
    match repos::find_by_id(ctx.conn, a.repo.id) {
        Ok(Some(r)) => match repo_json(ctx.app, ctx.conn, &r, a.perm) {
            Ok(v) => Resp::json(200, &v),
            Err(resp) => resp,
        },
        Ok(None) => not_found(&base, "The target couldn't be found.", None),
        Err(e) => ctx.app.internal(&e),
    }
}

/// `DELETE /repos/{o}/{r}` (owner-level, checked by the router).
pub fn delete_repo(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    match ctx.app.life.delete(ctx.conn, &a.repo, now()) {
        Ok(()) => Resp::no_content(),
        Err(e) => life_err(ctx.app, e),
    }
}

fn list_response(
    ctx: &Ctx,
    path: &str,
    rows: &[Repo],
    total: i64,
    page: i64,
    limit: i64,
    wrap: bool,
) -> Resp {
    let items = match listed(ctx, rows) {
        Ok(i) => i,
        Err(r) => return r,
    };
    if !wrap {
        return paged(ctx, path, total, page, limit, items);
    }
    let mut r = Resp::json(200, &json!({"ok": true, "data": items}))
        .with("x-total-count", total.to_string());
    if let Some(link) = paged(ctx, path, total, page, limit, vec![])
        .headers
        .iter()
        .find(|(k, _)| *k == "link")
    {
        r = r.with("link", link.1.clone());
    }
    r
}

fn query_list(ctx: &Ctx, filter: &Filter, sort: Sort, path: &str, wrap: bool) -> Resp {
    let (page, limit) = page_params(ctx);
    match repos::list_visible(
        ctx.conn,
        &ctx.who.user,
        token_public_only(ctx),
        filter,
        sort,
        page,
        limit,
    ) {
        Ok((rows, total)) => list_response(ctx, path, &rows, total, page, limit, wrap),
        Err(e) => ctx.app.internal(&e),
    }
}

/// `GET /repos/search`: `{"ok": true, "data": [...]}`; a `public-only` token sees nothing.
pub fn search(ctx: &mut Ctx) -> Resp {
    // `q` arrives percent-encoded with `+` for a space (form encoding).
    let q = ctx
        .req
        .param("q")
        .and_then(|v| crate::routes::percent_decode(&v.replace('+', " ")));
    let sort = if ctx.req.param("sort") == Some("alpha") {
        Sort::Alpha
    } else {
        Sort::Id
    };
    // Page links repeat the query, in the recorded order (alphabetical after limit and page).
    let mut extra: Vec<(&str, String)> = Vec::new();
    if let Some(raw) = ctx.req.param("q") {
        extra.push(("q", raw.to_string()));
    }
    if ctx.req.param("sort") == Some("alpha") {
        extra.push(("sort", "alpha".to_string()));
    }
    let (page, limit) = page_params(ctx);
    match repos::list_visible(
        ctx.conn,
        &ctx.who.user,
        token_public_only(ctx),
        &Filter { q, owner_id: None },
        sort,
        page,
        limit,
    ) {
        Ok((rows, total)) => {
            let items = match listed(ctx, &rows) {
                Ok(i) => i,
                Err(r) => return r,
            };
            let links = paged_with(ctx, "/repos/search", total, page, limit, &extra, vec![]);
            let mut r = Resp::json(200, &json!({"ok": true, "data": items}))
                .with("x-total-count", total.to_string());
            if let Some((_, link)) = links.headers.iter().find(|(k, _)| *k == "link") {
                r = r.with("link", link.clone());
            }
            r
        }
        Err(e) => ctx.app.internal(&e),
    }
}

/// `GET /user/repos`: every repository the caller can read.
pub fn list_user_repos(ctx: &mut Ctx) -> Resp {
    query_list(ctx, &Filter::default(), Sort::Id, "/user/repos", false)
}

/// `GET /orgs/{o}/repos`: 200 for any existing organization, listing only what the caller can read.
pub fn list_org_repos(ctx: &mut Ctx) -> Resp {
    let name = ctx.param("o").to_string();
    match store::find_by_login(ctx.conn, &name) {
        Ok(Some(org)) if org.is_org => {
            // The list is filtered by repository access whether or not the organization itself is
            // visible: a collaborator of a repository inside a private organization still sees it
            // (recorded K#55), and the counts are the visible count.
            let path = format!("/orgs/{}/repos", org.login);
            query_list(
                ctx,
                &Filter {
                    owner_id: Some(org.id),
                    ..Default::default()
                },
                Sort::Id,
                &path,
                false,
            )
        }
        Ok(_) => crate::api::org_missing(ctx.app, &name),
        Err(e) => ctx.app.internal(&e),
    }
}

fn collab_target(ctx: &Ctx) -> Result<User, Resp> {
    let name = ctx.param("u");
    match store::find_by_login(ctx.conn, name) {
        Ok(Some(u)) if !u.is_org => Ok(u),
        Ok(_) => Err(error(
            &ctx.app.base,
            422,
            &format!("user does not exist [uid: 0, name: {name}]"),
        )),
        Err(e) => Err(ctx.app.internal(&e)),
    }
}

/// `GET /repos/{o}/{r}/collaborators`: in the order they were added.
pub fn list_collaborators(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let (page, limit) = page_params(ctx);
    match repos::collaborators(ctx.conn, a.repo.id, page, limit) {
        Ok((rows, total)) => {
            let items = rows
                .iter()
                .map(|(u, _)| user_json(&ctx.app.base, u))
                .collect();
            let path = format!("/repos/{}/{}/collaborators", a.repo.owner, a.repo.name);
            paged(ctx, &path, total, page, limit, items)
        }
        Err(e) => ctx.app.internal(&e),
    }
}

/// `PUT /repos/{o}/{r}/collaborators/{u}` with `{"permission": read|write|admin}` (default write).
pub fn put_collaborator(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let target = match collab_target(ctx) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let base = ctx.app.base.clone();
    if b.get("permission")
        .is_some_and(|v| !v.is_string() && !v.is_null())
    {
        return error(&base, 422, "[Permission]: invalid permission");
    }
    let mode = match str_field(&b, "permission") {
        None => Perm::Write,
        Some(m) => match Perm::from_mode(&m) {
            Some(p) => p,
            None => return error(&base, 422, "[Permission]: invalid permission"),
        },
    };
    let is_owner = target.id == a.repo.owner_id
        || store::is_org_owner(ctx.conn, a.repo.owner_id, target.id).unwrap_or(false);
    if is_owner {
        return error(&base, 422, "the repository owner cannot be a collaborator");
    }
    match repos::set_collaborator(ctx.conn, a.repo.id, target.id, mode) {
        Ok(()) => Resp::no_content(),
        Err(e) => ctx.app.internal(&e),
    }
}

/// `DELETE /repos/{o}/{r}/collaborators/{u}`.
pub fn delete_collaborator(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let target = match collab_target(ctx) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match repos::remove_collaborator(ctx.conn, a.repo.id, target.id) {
        Ok(_) => Resp::no_content(),
        Err(e) => ctx.app.internal(&e),
    }
}

/// `GET /repos/{o}/{r}/collaborators/{u}/permission`.
pub fn collaborator_permission(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let target = match collab_target(ctx) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let owner = target.id == a.repo.owner_id
        || store::is_org_owner(ctx.conn, a.repo.owner_id, target.id).unwrap_or(false);
    let perm = if owner {
        "owner"
    } else {
        match repos::collaborator_mode(ctx.conn, a.repo.id, target.id) {
            Ok(Some(p)) => p.as_mode(),
            Ok(None) => "none",
            Err(e) => return ctx.app.internal(&e),
        }
    };
    let mut u = user_json(&ctx.app.base, &target);
    u["active"] = json!(false); // recorded
    Resp::json(
        200,
        &json!({"permission": perm, "role_name": perm, "user": u}),
    )
}

fn branch_json(ctx: &Ctx, a: &Access, br: &gitread::Branch) -> Result<Value, Resp> {
    let dir = ctx.app.life.repo_dir(a.repo.id);
    let c = gitread::commit(&ctx.app.life.git, &dir, &br.oid)
        .map_err(|e| git_read_err(ctx.app, ctx.conn, a.repo.id, e))?
        .ok_or_else(|| ctx.app.internal(&"branch points at no commit"))?;
    let who = |p: &gitread::Person| json!({"name": p.name, "email": p.email, "username": ""});
    let full = format!("{}/{}", a.repo.owner, a.repo.name);
    Ok(json!({
        "name": br.name,
        "commit": {
            "id": c.oid,
            "message": c.message,
            "url": format!("{}/{full}/commit/{}", ctx.app.base, c.oid),
            "author": who(&c.author),
            "committer": who(&c.committer),
            "verification": {"verified": false, "reason": "gpg.error.not_signed_commit", "signature": "", "signer": null, "payload": ""},
            "timestamp": rfc3339(c.committer.when),
            "added": null,
            "removed": null,
            "modified": null,
        },
        "protected": false,
        "required_approvals": 0,
        "enable_status_check": false,
        "status_check_contexts": [],
        "user_can_push": a.perm >= Perm::Write,
        "user_can_merge": a.perm >= Perm::Write,
        "effective_branch_protection_name": "",
    }))
}

/// Run a read of the repository on disk under its shared lock, answering as for a missing
/// repository when it is no longer live by the time the lock is held.
fn read_locked(ctx: &Ctx, a: &Access, f: impl FnOnce(&Ctx) -> Resp) -> Resp {
    match ctx.app.life.with_read(ctx.conn, a.repo.id, || f(ctx)) {
        Ok(Some(r)) => r,
        Ok(None) => not_found(&ctx.app.base, "The target couldn't be found.", None),
        Err(e) => ctx.app.internal(&e),
    }
}

fn no_branch(ctx: &Ctx, name: &str) -> Resp {
    not_found(
        &ctx.app.base,
        "The target couldn't be found.",
        Some(&format!("branch does not exist [name: {name}]")),
    )
}

/// `GET /repos/{o}/{r}/branches`: sorted by name; an empty repository answers `null`.
pub fn list_branches(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    read_locked(ctx, &a, |ctx| list_branches_inner(ctx, &a))
}

fn list_branches_inner(ctx: &Ctx, a: &Access) -> Resp {
    let all = match gitread::list_branches(&ctx.app.life.git, &ctx.app.life.repo_dir(a.repo.id)) {
        Ok(b) => b,
        Err(e) => return git_read_err(ctx.app, ctx.conn, a.repo.id, e),
    };
    if all.is_empty() {
        return Resp::json(200, &Value::Null).with("x-total-count", "0".into());
    }
    let (page, limit) = page_params(ctx);
    let total = all.len() as i64;
    let start = (((page - 1) * limit) as usize).min(all.len());
    let rows = &all[start..(start + limit as usize).min(all.len())];
    let items: Result<Vec<Value>, Resp> = rows.iter().map(|b| branch_json(ctx, a, b)).collect();
    match items {
        Ok(items) => paged(
            ctx,
            &format!("/repos/{}/{}/branches", a.repo.owner, a.repo.name),
            total,
            page,
            limit,
            items,
        ),
        Err(r) => r,
    }
}

/// `GET /repos/{o}/{r}/branches/{b..}`.
pub fn get_branch(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    read_locked(ctx, &a, |ctx| get_branch_inner(ctx, &a))
}

fn get_branch_inner(ctx: &Ctx, a: &Access) -> Resp {
    let name = ctx.param("b").to_string();
    match gitread::branch_oid(&ctx.app.life.git, &ctx.app.life.repo_dir(a.repo.id), &name) {
        Ok(Some(oid)) => match branch_json(ctx, a, &gitread::Branch { name, oid }) {
            Ok(v) => Resp::json(200, &v),
            Err(r) => r,
        },
        Ok(None) => no_branch(ctx, &name),
        Err(e) => git_read_err(ctx.app, ctx.conn, a.repo.id, e),
    }
}

/// `DELETE /repos/{o}/{r}/branches/{b..}`: the default branch stays (403, recorded).
pub fn delete_branch(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let name = ctx.param("b").to_string();
    if !refname::valid_branch(&name) {
        return no_branch(ctx, &name);
    }
    if name.eq_ignore_ascii_case(&a.repo.default_branch) {
        return error(&ctx.app.base, 403, "can not delete default branch");
    }
    match ctx.app.life.delete_branch(ctx.conn, &a.repo, &name) {
        Ok(()) => Resp::no_content(),
        Err(LifecycleError::NoSuchBranch) => no_branch(ctx, &name),
        Err(e) => life_err(ctx.app, e),
    }
}
