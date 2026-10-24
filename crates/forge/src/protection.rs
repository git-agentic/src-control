//! Branch protection rules: storage and the `/branch_protections` API.
//!
//! A rule names one branch exactly (case-insensitively, like [`policy::same_branch_name`]); glob
//! patterns, which Gitea also accepts, are refused rather than stored as a literal that protects
//! nothing. Only `enable_push`, `enable_status_check` and `status_check_contexts` are enforced; a
//! request that sets any other protection setting to a non-default value is refused, because
//! echoing a setting nothing enforces would read as protection that is not there. Rule changes run
//! under the repository's write gate, so they are ordered against server-made ref writes (see
//! `lifecycle`'s lock order); a push in flight is not coordinated (it reads the rules in the
//! `pre-receive` hook).

use crate::api::{body, str_field};
use crate::http::{error, not_found, Resp};
use crate::lifecycle::WriteRun;
use crate::policy::{Rule, Rules};
use crate::refname;
use crate::repo_api::acc;
use crate::repos::{Access, Perm};
use crate::routes::Ctx;
use crate::timefmt::{now, rfc3339};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::time::Duration;

/// How long a rule change waits for the repository's write gate.
const GATE_WAIT: Duration = Duration::from_secs(10);
const MAX_CONTEXTS: usize = 64;
const MAX_CONTEXT_LEN: usize = 255;

/// A stored rule with its timestamps.
pub struct Stored {
    pub rule: Rule,
    pub created: i64,
    pub updated: i64,
}

fn row(r: &rusqlite::Row) -> rusqlite::Result<Stored> {
    let contexts: Option<String> = r.get(3)?;
    Ok(Stored {
        rule: Rule {
            branch: r.get(0)?,
            enable_push: r.get::<_, i64>(1)? != 0,
            enable_status_check: r.get::<_, i64>(2)? != 0,
            // The column is only ever written from a validated Vec<String>; an unreadable value
            // reads as "no contexts" and the merge gate (which requires some when the check is on)
            // then refuses rather than passes.
            contexts: contexts.and_then(|c| serde_json::from_str(&c).ok()),
        },
        created: r.get(4)?,
        updated: r.get(5)?,
    })
}

const COLS: &str =
    "branch, enable_push, enable_status_check, status_check_contexts, created_unix, updated_unix";

/// Every rule of the repository, oldest first.
pub fn list(conn: &Connection, repo_id: i64) -> rusqlite::Result<Vec<Stored>> {
    let mut st = conn.prepare(&format!(
        "SELECT {COLS} FROM branch_protections WHERE repo_id = ?1 ORDER BY id"
    ))?;
    let rows = st.query_map([repo_id], row)?.collect();
    rows
}

/// The rules the policy functions take.
pub fn load(conn: &Connection, repo_id: i64) -> rusqlite::Result<Rules> {
    Ok(Rules(
        list(conn, repo_id)?.into_iter().map(|s| s.rule).collect(),
    ))
}

fn find(conn: &Connection, repo_id: i64, name: &str) -> rusqlite::Result<Option<Stored>> {
    let lower = name.to_lowercase();
    conn.query_row(
        &format!("SELECT {COLS} FROM branch_protections WHERE repo_id = ?1 AND lower_branch = ?2"),
        params![repo_id, lower],
        row,
    )
    .optional()
}

fn write_contexts(c: &Option<Vec<String>>) -> Option<String> {
    c.as_ref()
        .map(|v| serde_json::to_string(v).expect("strings serialize"))
}

fn rule_json(s: &Stored) -> Value {
    let r = &s.rule;
    json!({
        "branch_name": r.branch,
        "rule_name": r.branch,
        "enable_push": r.enable_push,
        "enable_push_whitelist": false,
        "push_whitelist_usernames": [],
        "push_whitelist_teams": [],
        "push_whitelist_deploy_keys": false,
        "enable_merge_whitelist": false,
        "merge_whitelist_usernames": [],
        "merge_whitelist_teams": [],
        "enable_status_check": r.enable_status_check,
        "status_check_contexts": r.contexts,
        "required_approvals": 0,
        "enable_approvals_whitelist": false,
        "approvals_whitelist_username": [],
        "approvals_whitelist_teams": [],
        "block_on_rejected_reviews": false,
        "block_on_official_review_requests": false,
        "block_on_outdated_branch": false,
        "dismiss_stale_approvals": false,
        "ignore_stale_approvals": false,
        "require_signed_commits": false,
        "protected_file_patterns": "",
        "unprotected_file_patterns": "",
        "created_at": rfc3339(s.created),
        "updated_at": rfc3339(s.updated),
    })
}

/// Settings of Gitea's protection object that `sc-forge` does not enforce. Present with a
/// non-default value they are refused (the 1.26.2 additions included).
const UNSUPPORTED: &[&str] = &[
    "enable_push_whitelist",
    "push_whitelist_usernames",
    "push_whitelist_teams",
    "push_whitelist_deploy_keys",
    "enable_merge_whitelist",
    "merge_whitelist_usernames",
    "merge_whitelist_teams",
    "required_approvals",
    "enable_approvals_whitelist",
    "approvals_whitelist_username",
    "approvals_whitelist_teams",
    "block_on_rejected_reviews",
    "block_on_official_review_requests",
    "block_on_outdated_branch",
    "dismiss_stale_approvals",
    "ignore_stale_approvals",
    "require_signed_commits",
    "protected_file_patterns",
    "unprotected_file_patterns",
    "priority",
    "enable_force_push",
    "enable_force_push_allowlist",
    "force_push_allowlist_usernames",
    "force_push_allowlist_teams",
    "force_push_allowlist_deploy_keys",
    "block_admin_merge_override",
];

fn is_default(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_i64() == Some(0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

fn has_glob(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

fn contexts_of(v: &Value) -> Result<Option<Vec<String>>, String> {
    let Value::Array(items) = v else {
        return if v.is_null() {
            Ok(None)
        } else {
            Err("[StatusCheckContexts]: must be a list of strings".into())
        };
    };
    if items.len() > MAX_CONTEXTS {
        return Err(format!(
            "[StatusCheckContexts]: at most {MAX_CONTEXTS} contexts"
        ));
    }
    let mut out = Vec::new();
    for i in items {
        let Some(c) = i.as_str() else {
            return Err("[StatusCheckContexts]: must be a list of strings".into());
        };
        if c.is_empty() || c.len() > MAX_CONTEXT_LEN || c.chars().any(char::is_control) {
            return Err(format!(
                "[StatusCheckContexts]: a context is 1 to {MAX_CONTEXT_LEN} bytes without control characters"
            ));
        }
        if has_glob(c) {
            return Err("[StatusCheckContexts]: context patterns are not supported".into());
        }
        if !out.contains(&c.to_string()) {
            out.push(c.to_string());
        }
    }
    Ok(Some(out))
}

/// The enforced settings out of a request body, applied over `base` (a PATCH) or the defaults
/// (a create). Every refusal is a 422 text.
fn settings(b: &Value, mut base: Rule) -> Result<Rule, String> {
    for k in UNSUPPORTED {
        if b.get(k).is_some_and(|v| !is_default(v)) {
            return Err(format!("unsupported branch protection setting: {k}"));
        }
    }
    for (k, slot) in [
        ("enable_push", &mut base.enable_push),
        ("enable_status_check", &mut base.enable_status_check),
    ] {
        match b.get(k) {
            None | Some(Value::Null) => {}
            Some(Value::Bool(v)) => *slot = *v,
            Some(_) => return Err(format!("[{k}]: must be a boolean")),
        }
    }
    if let Some(v) = b.get("status_check_contexts") {
        base.contexts = contexts_of(v)?;
    }
    if base.enable_status_check && base.contexts.as_ref().is_none_or(Vec::is_empty) {
        return Err("status_check_contexts is required when enable_status_check is set".into());
    }
    Ok(base)
}

fn require_admin(ctx: &Ctx, a: &Access) -> Result<(), Resp> {
    if a.perm >= Perm::Admin {
        return Ok(());
    }
    Err(error(
        &ctx.app.base,
        403,
        "user should be an owner or a collaborator with admin write of a repository",
    ))
}

fn missing(ctx: &Ctx) -> Resp {
    not_found(&ctx.app.base, "The target couldn't be found.", None)
}

/// Run `f` under the write gate and answer for the gate's outcomes.
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

/// `GET /repos/{o}/{r}/branch_protections`.
pub fn list_rules(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    match list(ctx.conn, a.repo.id) {
        Ok(rows) => Resp::json(200, &Value::Array(rows.iter().map(rule_json).collect())),
        Err(e) => ctx.app.internal(&e),
    }
}

/// `GET /repos/{o}/{r}/branch_protections/{b..}`.
pub fn get_rule(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    match find(ctx.conn, a.repo.id, ctx.param("b")) {
        Ok(Some(s)) => Resp::json(200, &rule_json(&s)),
        Ok(None) => missing(ctx),
        Err(e) => ctx.app.internal(&e),
    }
}

/// `POST /repos/{o}/{r}/branch_protections`.
pub fn create_rule(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    if let Err(r) = require_admin(ctx, &a) {
        return r;
    }
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let (name, rule_name) = (str_field(&b, "branch_name"), str_field(&b, "rule_name"));
    let name = match (name, rule_name) {
        (Some(x), Some(y)) if x != y => {
            return error(
                &ctx.app.base,
                422,
                "branch_name and rule_name must be the same",
            )
        }
        (Some(x), _) | (None, Some(x)) if !x.is_empty() => x,
        _ => return error(&ctx.app.base, 422, "[BranchName]: Required"),
    };
    if has_glob(&name) {
        return error(
            &ctx.app.base,
            422,
            "branch name patterns are not supported: name one branch",
        );
    }
    if !refname::valid_branch(&name) {
        return error(&ctx.app.base, 422, "[BranchName]: not a valid branch name");
    }
    let rule = match settings(
        &b,
        Rule {
            branch: name,
            enable_push: false,
            enable_status_check: false,
            contexts: None,
        },
    ) {
        Ok(r) => r,
        Err(m) => return error(&ctx.app.base, 422, &m),
    };
    gated(ctx, &a, || {
        match find(ctx.conn, a.repo.id, &rule.branch) {
            Ok(Some(_)) => return error(&ctx.app.base, 403, "Branch protection already exist"),
            Ok(None) => {}
            Err(e) => return ctx.app.internal(&e),
        }
        let t = now();
        let inserted = ctx.conn.execute(
            "INSERT INTO branch_protections (repo_id, branch, lower_branch, enable_push, \
             enable_status_check, status_check_contexts, created_unix, updated_unix) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![
                a.repo.id,
                rule.branch,
                rule.branch.to_lowercase(),
                rule.enable_push,
                rule.enable_status_check,
                write_contexts(&rule.contexts),
                t
            ],
        );
        match inserted {
            Ok(_) => Resp::json(
                201,
                &rule_json(&Stored {
                    rule,
                    created: t,
                    updated: t,
                }),
            ),
            Err(e) => ctx.app.internal(&e),
        }
    })
}

/// `PATCH /repos/{o}/{r}/branch_protections/{b..}`: the settings present in the body replace the
/// stored ones; the rule's name does not change.
pub fn patch_rule(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    if let Err(r) = require_admin(ctx, &a) {
        return r;
    }
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let name = ctx.param("b").to_string();
    gated(ctx, &a, || {
        let cur = match find(ctx.conn, a.repo.id, &name) {
            Ok(Some(s)) => s,
            Ok(None) => return missing(ctx),
            Err(e) => return ctx.app.internal(&e),
        };
        let rule = match settings(&b, cur.rule.clone()) {
            Ok(r) => r,
            Err(m) => return error(&ctx.app.base, 422, &m),
        };
        let t = now();
        let done = ctx.conn.execute(
            "UPDATE branch_protections SET enable_push = ?1, enable_status_check = ?2, \
             status_check_contexts = ?3, updated_unix = ?4 WHERE repo_id = ?5 AND lower_branch = ?6",
            params![
                rule.enable_push,
                rule.enable_status_check,
                write_contexts(&rule.contexts),
                t,
                a.repo.id,
                rule.branch.to_lowercase()
            ],
        );
        match done {
            Ok(_) => Resp::json(
                200,
                &rule_json(&Stored {
                    rule,
                    created: cur.created,
                    updated: t,
                }),
            ),
            Err(e) => ctx.app.internal(&e),
        }
    })
}

/// `DELETE /repos/{o}/{r}/branch_protections/{b..}`.
pub fn delete_rule(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    if let Err(r) = require_admin(ctx, &a) {
        return r;
    }
    let lower = ctx.param("b").to_lowercase();
    gated(ctx, &a, || {
        match ctx.conn.execute(
            "DELETE FROM branch_protections WHERE repo_id = ?1 AND lower_branch = ?2",
            params![a.repo.id, lower],
        ) {
            Ok(0) => missing(ctx),
            Ok(_) => Resp::no_content(),
            Err(e) => ctx.app.internal(&e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Rule {
        Rule {
            branch: "main".into(),
            enable_push: false,
            enable_status_check: false,
            contexts: None,
        }
    }

    #[test]
    fn defaults_and_flags_apply_over_the_base() {
        let r = settings(&json!({"enable_push": true}), base()).unwrap();
        assert!(r.enable_push && !r.enable_status_check && r.contexts.is_none());
        let r = settings(
            &json!({"enable_status_check": true, "status_check_contexts": ["ci/test", "ci/test"]}),
            base(),
        )
        .unwrap();
        assert_eq!(
            r.contexts,
            Some(vec!["ci/test".to_string()]),
            "deduplicated"
        );
        let r = settings(&json!({"enable_status_check": false}), r).unwrap();
        assert_eq!(r.contexts.as_deref(), Some(&["ci/test".to_string()][..]));
    }

    #[test]
    fn unsupported_settings_are_refused_only_when_set() {
        assert!(settings(&json!({"required_approvals": 0, "enable_push_whitelist": false, "protected_file_patterns": ""}), base()).is_ok());
        for (k, v) in [
            ("required_approvals", json!(2)),
            ("enable_merge_whitelist", json!(true)),
            ("require_signed_commits", json!(true)),
            ("block_on_outdated_branch", json!(true)),
            ("push_whitelist_usernames", json!(["a"])),
            ("protected_file_patterns", json!("*.lock")),
            ("enable_force_push", json!(true)),
        ] {
            let e = settings(&json!({ k: v }), base()).unwrap_err();
            assert!(e.contains(k), "{k}: {e}");
        }
    }

    #[test]
    fn status_check_needs_contexts_and_contexts_are_literal() {
        assert!(settings(&json!({"enable_status_check": true}), base()).is_err());
        assert!(settings(
            &json!({"enable_status_check": true, "status_check_contexts": []}),
            base()
        )
        .is_err());
        for bad in [
            json!(["ci/*"]),
            json!(["a?"]),
            json!([""]),
            json!([1]),
            json!("x"),
        ] {
            assert!(
                settings(&json!({"status_check_contexts": bad}), base()).is_err(),
                "{bad}"
            );
        }
        let many: Vec<String> = (0..=MAX_CONTEXTS).map(|i| format!("c{i}")).collect();
        assert!(settings(&json!({ "status_check_contexts": many }), base()).is_err());
        assert!(settings(&json!({"enable_push": "yes"}), base()).is_err());
    }
}
