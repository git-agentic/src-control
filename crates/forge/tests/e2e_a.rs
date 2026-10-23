//! Scenario A/B/R/X of the recorded contract, F1 slice: meta routes, users,
//! organizations, tokens and the credential rules. Texts and statuses are the
//! ones recorded from Gitea 1.22.6 unless `departures.json` says otherwise.
#![cfg(unix)]

mod common;
use common::*;
use serde_json::json;

const USER_KEYS: &[&str] = &[
    "id",
    "login",
    "login_name",
    "source_id",
    "full_name",
    "email",
    "avatar_url",
    "html_url",
    "language",
    "is_admin",
    "last_login",
    "created",
    "restricted",
    "active",
    "prohibit_login",
    "location",
    "website",
    "description",
    "visibility",
    "followers_count",
    "following_count",
    "starred_repos_count",
    "username",
];

fn has_keys(v: &serde_json::Value, keys: &[&str]) {
    for k in keys {
        assert!(v.get(*k).is_some(), "missing key {k} in {v}");
    }
}

#[test]
fn version_healthz_and_anonymous_access() {
    let s = Srv::start();
    let r = s.get("/api/v1/version", &token(&s.admin));
    assert_eq!((r.status, r.json()), (200, json!({"version": "1.22.6"})));
    assert_eq!(r.headers["content-type"], "application/json;charset=utf-8");
    assert!(
        r.headers["server"].starts_with("sc-forge/"),
        "identity lives in the Server header"
    );

    let anon = s.send("GET", "/api/v1/version", None, None);
    assert_eq!(anon.status, 403);
    assert_eq!(
        anon.json(),
        json!({"message": "Only signed in user is allowed to call APIs."}),
        "no url key"
    );

    let h = s.send("GET", "/api/healthz", None, None);
    assert_eq!(h.status, 200);
    assert_eq!(h.headers["content-type"], "application/json");
    assert_eq!(h.json()["status"], "pass");
}

#[test]
fn current_user_and_bad_credentials() {
    let s = Srv::start();
    let r = s.get("/api/v1/user", &token(&s.admin));
    assert_eq!(r.status, 200);
    has_keys(&r.json(), USER_KEYS);
    assert_eq!(r.json()["login"], "siteadmin");
    assert_eq!(r.json()["is_admin"], true);
    assert_eq!(r.json()["html_url"], format!("{}/siteadmin", s.base));

    let bad = s.get("/api/v1/user", &token("0".repeat(40).as_str()));
    assert_eq!(bad.status, 401);
    assert_eq!(bad.msg(), "user does not exist [uid: 0, name: ]");
    assert_eq!(bad.json()["url"], format!("{}/api/swagger", s.base));

    let anon = s.send("GET", "/api/v1/user", None, None);
    assert_eq!(
        (anon.status, anon.msg().as_str()),
        (403, "Only signed in user is allowed to call APIs.")
    );
}

#[test]
fn users_orgs_and_visibility() {
    let s = Srv::start();
    let adm = token(&s.admin);
    let body = json!({"username": "alice", "email": "alice@example.invalid", "password": "pw-alice-1234", "must_change_password": false});
    let r = s.post("/api/v1/admin/users", &adm, body.clone());
    assert_eq!(r.status, 201);
    has_keys(&r.json(), USER_KEYS);
    assert_eq!(r.json()["login_name"], "");

    let dup = s.post("/api/v1/admin/users", &adm, body);
    assert_eq!(
        (dup.status, dup.msg().as_str()),
        (422, "user already exists [name: alice]")
    );
    let case = s.post(
        "/api/v1/admin/users",
        &adm,
        json!({"username": "Alice", "email": "a@example.invalid", "password": "x"}),
    );
    assert_eq!(
        (case.status, case.msg().as_str()),
        (422, "user already exists [name: Alice]"),
        "names are case-insensitive"
    );

    let patch = s.send("PATCH", "/api/v1/admin/users/alice", Some(&adm), Some(&json!({"login_name": "alice", "source_id": 0, "visibility": "private", "must_change_password": false})));
    assert_eq!(patch.status, 200);
    assert_eq!(
        (
            patch.json()["login_name"].as_str(),
            patch.json()["visibility"].as_str()
        ),
        (Some("alice"), Some("private"))
    );
    assert_eq!(s.get("/api/v1/users/alice", &adm).status, 200);
    let miss = s.get("/api/v1/users/nobody-here", &adm);
    assert_eq!(
        (miss.status, miss.msg().as_str()),
        (404, "user redirect does not exist [name: nobody-here]")
    );

    // A private user is invisible to another user.
    let bob_pw = s.mk_user("bob");
    let bob = s.mk_token("bob", &bob_pw, "t", &["read:user", "read:organization"]);
    assert_eq!(s.get("/api/v1/users/alice", &token(&bob)).status, 404);

    // Organizations.
    let org = json!({"username": "acme", "full_name": "Acme", "visibility": "private"});
    let o = s.post("/api/v1/orgs", &adm, org.clone());
    assert_eq!(o.status, 201);
    assert_eq!(o.json()["name"], "acme");
    assert_eq!(o.json()["repo_admin_change_team_access"], false);
    let od = s.post("/api/v1/orgs", &adm, org);
    assert_eq!(
        (od.status, od.msg().as_str()),
        (422, "user already exists [name: acme]")
    );
    let nf = s.get("/api/v1/orgs/nobody-org", &adm);
    assert_eq!(nf.status, 404);
    assert_eq!(nf.json()["message"], "GetOrgByName");
    assert_eq!(
        nf.json()["errors"],
        json!(["user redirect does not exist [name: nobody-org]"])
    );
    // Private org: owner and admin see it, others get the recorded 404.
    let hidden = s.get("/api/v1/orgs/acme", &token(&bob));
    assert_eq!(
        (hidden.status, hidden.msg().as_str()),
        (404, "HasOrgOrUserVisible")
    );
    assert_eq!(hidden.json()["errors"], serde_json::Value::Null);
    let perms = s.get("/api/v1/users/siteadmin/orgs/acme/permissions", &adm);
    assert_eq!(
        perms.json(),
        json!({"is_owner": true, "is_admin": true, "can_write": true, "can_read": true, "can_create_repository": true})
    );
    assert_eq!(
        s.get("/api/v1/users/alice/orgs/acme/permissions", &adm)
            .msg(),
        "HasOrgOrUserVisible"
    );
}

#[test]
fn name_rules_match_the_recordings() {
    let s = Srv::start();
    let adm = token(&s.admin);
    for (name, status, msg) in [
        ("api", 422, "name is reserved [name: api]"),
        ("user", 422, "name is reserved [name: user]"),
        (".dot", 422, "[Username]: invalid username"),
        ("-dash", 422, "[Username]: invalid username"),
        ("bad name", 422, "[Username]: invalid username"),
        ("trail.git", 201, ""),
    ] {
        let r = s.post(
            "/api/v1/admin/users",
            &adm,
            json!({"username": name, "email": "x@example.invalid", "password": "pw"}),
        );
        assert_eq!(r.status, status, "{name}");
        if status != 201 {
            assert_eq!(r.msg(), msg, "{name}");
        }
    }
    let org = s.post("/api/v1/orgs", &adm, json!({"username": "x".repeat(41)}));
    assert_eq!(
        (org.status, org.msg().as_str()),
        (422, "[UserName]: MaxSize")
    );
    let org = s.post("/api/v1/orgs", &adm, json!({"username": "-dash"}));
    assert_eq!(org.msg(), "[UserName]: invalid username");
}

#[test]
fn token_lifecycle_with_the_users_password() {
    let s = Srv::start();
    let pw = s.mk_user("alice");
    let basic_alice = basic("alice", &pw);
    let a = s.post(
        "/api/v1/users/alice/tokens",
        &basic_alice,
        json!({"name": "ci", "scopes": ["read:repository"]}),
    );
    assert_eq!(a.status, 201);
    let a = a.json();
    assert_eq!(a["sha1"].as_str().unwrap().len(), 40);
    assert_eq!(a["token_last_eight"], a["sha1"].as_str().unwrap()[32..]);
    assert_eq!(a["scopes"], json!(["read:repository"]));
    // Scopes are normalized: write shadows read.
    let b = s.post(
        "/api/v1/users/alice/tokens",
        &basic_alice,
        json!({"name": "tmp", "scopes": ["read:repository", "write:repository"]}),
    );
    assert_eq!(b.json()["scopes"], json!(["write:repository"]));
    let c = s.post(
        "/api/v1/users/alice/tokens",
        &basic_alice,
        json!({"name": "ord", "scopes": ["read:user", "read:organization", "write:repository"]}),
    );
    assert_eq!(
        c.json()["scopes"],
        json!(["read:organization", "write:repository", "read:user"])
    );

    let l = s.get("/api/v1/users/alice/tokens", &basic_alice);
    assert_eq!((l.status, l.headers["x-total-count"].as_str()), (200, "3"));
    let mut names: Vec<String> = l
        .json()
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort(); // order is covered by token_lists_are_newest_first; same-second creations tie
    assert_eq!(names, ["ci", "ord", "tmp"]);
    assert_eq!(
        l.json()[0]["sha1"],
        "",
        "the secret is shown once, at creation"
    );

    let dup = s.post(
        "/api/v1/users/alice/tokens",
        &basic_alice,
        json!({"name": "ci", "scopes": ["all"]}),
    );
    assert_eq!(
        (dup.status, dup.msg().as_str()),
        (400, "access token name has been used already")
    );
    let del = s.send(
        "DELETE",
        &format!("/api/v1/users/alice/tokens/{}", b.json()["id"]),
        Some(&basic_alice),
        None,
    );
    assert_eq!((del.status, del.raw.len()), (204, 0));
    assert_eq!(
        s.get("/api/v1/users/alice/tokens", &basic_alice).headers["x-total-count"],
        "2"
    );
    // A minted token works at once, and a deleted one stops working.
    assert_eq!(
        s.get("/api/v1/user", &token(a["sha1"].as_str().unwrap()))
            .status,
        403,
        "read:repository lacks read:user"
    );
    let user_tok = s.mk_token("alice", &pw, "u", &["read:user"]);
    assert_eq!(s.get("/api/v1/user", &token(&user_tok)).status, 200);
    s.send(
        "DELETE",
        "/api/v1/users/alice/tokens/u",
        Some(&basic_alice),
        None,
    );
    assert_eq!(s.get("/api/v1/user", &token(&user_tok)).status, 401);
}

#[test]
fn token_request_validation_texts() {
    let s = Srv::start();
    let pw = s.mk_user("alice");
    let a = basic("alice", &pw);
    let t = |b| s.post("/api/v1/users/alice/tokens", &a, b);
    let r = t(json!({"name": "x", "scopes": ["nonsense"]}));
    assert_eq!(
        (r.status, r.msg().as_str()),
        (
            400,
            "invalid access token scope provided: invalid access token scope: nonsense"
        )
    );
    let r = t(json!({"name": "x"}));
    assert_eq!(
        (r.status, r.msg().as_str()),
        (400, "access token must have a scope")
    );
    let r = t(json!({"name": "", "scopes": ["all"]}));
    assert_eq!((r.status, r.msg().as_str()), (422, "[Name]: Required"));
}

#[test]
fn scope_enforcement_names_the_missing_scope() {
    let s = Srv::start();
    let pw = s.mk_user("alice");
    let ro = s.mk_token("alice", &pw, "ro", &["read:repository"]);
    for (method, path, want) in [
        ("GET", "/api/v1/user", "[read:user]"),
        ("POST", "/api/v1/orgs/acme/repos", "[write:organization]"),
        ("GET", "/api/v1/admin/users", "[read:admin]"),
        ("POST", "/api/v1/admin/users", "[write:admin]"),
    ] {
        let r = s.send(method, path, Some(&token(&ro)), Some(&json!({})));
        assert_eq!(r.status, 403, "{method} {path}");
        assert_eq!(
            r.msg(),
            format!("token does not have at least one of required scope(s): {want}")
        );
    }
    // An all-scope token of a non-admin still cannot use admin routes.
    let all = s.mk_token("alice", &pw, "all", &["all"]);
    assert_eq!(s.get("/api/v1/admin/users", &token(&all)).status, 403);
    // A write scope satisfies a read requirement.
    let wr = s.mk_token("alice", &pw, "wr", &["write:user"]);
    assert_eq!(s.get("/api/v1/user", &token(&wr)).status, 200);
}

#[test]
fn every_token_credential_form_authenticates_on_ordinary_routes() {
    let s = Srv::start();
    let t = &s.admin;
    for (label, auth) in [
        ("token header", token(t)),
        ("Bearer", format!("Bearer {t}")),
        ("basic, token as password", basic("siteadmin", t)),
        ("basic, any username", basic("someone", t)),
        ("basic, oauth2", basic("oauth2", t)),
        ("basic, token as username", basic(t, "")),
    ] {
        let r = s.get("/api/v1/user", &auth);
        assert_eq!(
            (r.status, r.json()["login"].as_str()),
            (200, Some("siteadmin")),
            "{label}"
        );
    }
    let bad = "f".repeat(40);
    let r = s.get("/api/v1/user", &format!("Bearer {bad}"));
    assert_eq!(
        (r.status, r.msg().as_str()),
        (401, "user does not exist [uid: 0, name: ]")
    );
    let r = s.get("/api/v1/user", &basic(&bad, ""));
    assert_eq!(
        (r.status, r.msg()),
        (401, format!("user does not exist [uid: 0, name: {bad}]"))
    );
}

#[test]
fn a_users_password_is_never_a_credential_on_ordinary_routes() {
    let s = Srv::start();
    let pw = s.mk_user("alice");
    let r = s.get("/api/v1/user", &basic("alice", &pw));
    assert_eq!(r.status, 401);
    assert!(r.msg().to_lowercase().contains("auth"), "{}", r.msg());
    // ...including the site admin's own password.
    let r = s.get("/api/v1/user", &basic("siteadmin", "admin-pw-1"));
    assert_eq!(r.status, 401);
}

#[test]
fn a_token_can_never_mint_or_list_tokens() {
    let s = Srv::start();
    let pw = s.mk_user("alice");
    let all = s.mk_token("alice", &pw, "all", &["all"]);
    let body = json!({"name": "via-all-token", "scopes": ["all"]});
    for (label, auth) in [
        ("token header", token(&all)),
        ("Bearer", format!("Bearer {all}")),
        ("token as Basic password", basic("alice", &all)),
        ("token as Basic username", basic(&all, "")),
    ] {
        let r = s.post("/api/v1/users/alice/tokens", &auth, body.clone());
        assert!(r.status == 401 || r.status == 403, "{label}: {}", r.status);
        assert!(
            r.msg().to_lowercase().contains("password"),
            "{label}: {}",
            r.msg()
        );
        assert_eq!(
            s.get("/api/v1/users/alice/tokens", &auth).status,
            r.status,
            "{label} list"
        );
    }
    // A read-only token as the password cannot widen itself either.
    let ro = s.mk_token("alice", &pw, "ro", &["read:repository"]);
    let r = s.post(
        "/api/v1/users/alice/tokens",
        &basic("alice", &ro),
        json!({"name": "minted", "scopes": ["all"]}),
    );
    assert!(r.status == 401 || r.status == 403);
    assert!(s
        .get("/api/v1/users/alice/tokens", &basic("alice", &pw))
        .json()
        .as_array()
        .unwrap()
        .iter()
        .all(|t| t["name"] != "minted"));
    // Anonymous is refused with a password-class message, not served.
    let r = s.send("POST", "/api/v1/users/alice/tokens", None, Some(&body));
    assert_eq!(r.status, 401);
    assert!(r.msg().contains("password"));
}

#[test]
fn alices_password_cannot_mint_bobs_tokens_but_a_site_admins_can() {
    let s = Srv::start();
    let alice_pw = s.mk_user("alice");
    s.mk_user("bot");
    let body = json!({"name": "stolen", "scopes": ["all"]});
    let r = s.post(
        "/api/v1/users/bot/tokens",
        &basic("alice", &alice_pw),
        body.clone(),
    );
    assert_eq!(
        (r.status, r.msg().as_str()),
        (
            403,
            "doer should be the site admin or be same as the contextUser"
        )
    );
    let r = s.get("/api/v1/users/bot/tokens", &basic("alice", &alice_pw));
    assert_eq!(
        (r.status, r.msg().as_str()),
        (
            403,
            "doer should be the site admin or be same as the contextUser"
        )
    );
    // Even when bot does not exist, a non-admin learns nothing.
    assert_eq!(
        s.post(
            "/api/v1/users/ghost/tokens",
            &basic("alice", &alice_pw),
            body.clone()
        )
        .status,
        403
    );

    // A site admin authenticating with a password may; with a token may not.
    s.post("/api/v1/admin/users", &token(&s.admin), json!({"username": "siteowner", "email": "o@example.invalid", "password": "owner-pw-1", "must_change_password": false}));
    s.send(
        "PATCH",
        "/api/v1/admin/users/siteowner",
        Some(&token(&s.admin)),
        Some(&json!({"admin": true})),
    );
    let r = s.post(
        "/api/v1/users/bot/tokens",
        &basic("siteowner", "owner-pw-1"),
        json!({"name": "by-admin", "scopes": ["read:repository"]}),
    );
    assert_eq!(r.status, 201);
    let r = s.post(
        "/api/v1/users/bot/tokens",
        &token(&s.admin),
        json!({"name": "by-admin-token", "scopes": ["read:repository"]}),
    );
    assert_eq!(r.status, 401);
    let r = s.post(
        "/api/v1/users/ghost/tokens",
        &basic("siteowner", "owner-pw-1"),
        body,
    );
    assert_eq!(
        (r.status, r.msg().as_str()),
        (404, "user redirect does not exist [name: ghost]")
    );
}

#[test]
fn wrong_passwords_are_indistinguishable_and_never_reveal_what_the_secret_was() {
    let s = Srv::start();
    let pw = s.mk_user("alice");
    let org = s.post(
        "/api/v1/orgs",
        &token(&s.admin),
        json!({"username": "acme"}),
    );
    assert_eq!(org.status, 201);
    let ro = s.mk_token("alice", &pw, "ro", &["read:repository"]);
    let body = json!({"name": "a", "scopes": ["all"]});
    let attempts = [
        s.post(
            "/api/v1/users/alice/tokens",
            &basic("alice", "nope"),
            body.clone(),
        ),
        s.post(
            "/api/v1/users/nobody/tokens",
            &basic("nobody", "nope"),
            body.clone(),
        ),
        s.post(
            "/api/v1/users/acme/tokens",
            &basic("acme", "nope"),
            body.clone(),
        ), // an organization name
        s.post(
            "/api/v1/users/alice/tokens",
            &basic("alice", &ro),
            body.clone(),
        ), // a valid token as the password
        s.post(
            "/api/v1/users/alice/tokens",
            &basic("alice", &s.admin),
            body.clone(),
        ), // someone else's token
    ];
    for a in &attempts {
        assert_eq!(a.status, 401);
        assert_eq!(
            a.raw, attempts[0].raw,
            "same body whatever the credential was: no account or token oracle"
        );
    }
    // The right password still works straight after failures (backoff is not a lockout).
    assert_eq!(
        s.post("/api/v1/users/alice/tokens", &basic("alice", &pw), body)
            .status,
        201
    );
}

#[test]
fn failed_passwords_are_delayed_and_a_flooding_source_is_refused() {
    use std::time::{Duration, Instant};
    let s = Srv::start_backoff(scl_forge::limits::Backoff::new(
        4,
        Duration::from_millis(400),
    ));
    let pw = s.mk_user("alice");
    let body = json!({"name": "a", "scopes": ["all"]});
    let t = Instant::now();
    for _ in 0..3 {
        assert_eq!(
            s.post(
                "/api/v1/users/alice/tokens",
                &basic("alice", "bad"),
                body.clone()
            )
            .status,
            401
        );
    }
    assert!(
        t.elapsed() >= Duration::from_millis(50 + 100 + 200),
        "delays double per failure: {:?}",
        t.elapsed()
    );
    // The fourth attempt uses the last unit of the budget; the fifth is refused before any verification.
    assert_eq!(
        s.post(
            "/api/v1/users/alice/tokens",
            &basic("alice", &pw),
            body.clone()
        )
        .status,
        201
    );
    for _ in 0..3 {
        s.post(
            "/api/v1/users/alice/tokens",
            &basic("alice", "bad"),
            body.clone(),
        );
    }
    let r = s.post(
        "/api/v1/users/alice/tokens",
        &basic("alice", &pw),
        body.clone(),
    );
    assert_eq!(r.status, 429);
    assert_eq!(r.headers["retry-after"], "60");
    // Token routes are the only place passwords are tried; ordinary routes stay open to tokens.
    assert_eq!(s.get("/api/v1/user", &token(&s.admin)).status, 200);
}

#[test]
fn must_change_password_blocks_password_authentication() {
    let s = Srv::start();
    s.post(
        "/api/v1/admin/users",
        &token(&s.admin),
        json!({"username": "newbie", "email": "n@example.invalid", "password": "temp-pw-1"}),
    );
    let r = s.post(
        "/api/v1/users/newbie/tokens",
        &basic("newbie", "temp-pw-1"),
        json!({"name": "a", "scopes": ["all"]}),
    );
    assert_eq!(
        r.status, 403,
        "the default is must_change_password=true, as in Gitea"
    );
}

#[test]
fn admin_cli_changes_are_visible_to_the_running_server() {
    let s = Srv::start();
    let (pw1, pw2) = (scl_crypto::generate_token(), scl_crypto::generate_token());
    scl_forge::admin::user_create(&s.dir, "carol", &pw1, "c@example.invalid", false, false)
        .unwrap();
    let t = scl_forge::admin::generate_access_token(&s.dir, "carol", "cli", &["read:user".into()])
        .unwrap();
    assert_eq!(s.get("/api/v1/user", &token(&t)).json()["login"], "carol");
    scl_forge::admin::user_change_password(&s.dir, "carol", &pw2, false).unwrap();
    assert_eq!(
        s.post(
            "/api/v1/users/carol/tokens",
            &basic("carol", &pw1),
            json!({"name": "o", "scopes": ["all"]})
        )
        .status,
        401
    );
    assert_eq!(
        s.post(
            "/api/v1/users/carol/tokens",
            &basic("carol", &pw2),
            json!({"name": "n", "scopes": ["all"]})
        )
        .status,
        201
    );
    scl_forge::admin::org_create(&s.dir, "cliorg", "carol").unwrap();
    assert_eq!(s.get("/api/v1/orgs/cliorg", &token(&s.admin)).status, 200);
    assert!(scl_forge::admin::user_create(
        &s.dir,
        "carol",
        &pw1,
        "c@example.invalid",
        false,
        false
    )
    .is_err());
    assert!(
        scl_forge::admin::generate_access_token(&s.dir, "carol", "cli", &["all".into()]).is_err(),
        "duplicate token name"
    );
}

#[test]
fn expired_tokens_are_refused_like_unknown_ones() {
    let s = Srv::start();
    let pw = s.mk_user("alice");
    let t = s.mk_token("alice", &pw, "short", &["read:user"]);
    let conn = scl_forge::db::connect(&s.dir).unwrap();
    conn.execute(
        "UPDATE tokens SET expires_unix = 1 WHERE name = 'short'",
        [],
    )
    .unwrap();
    let r = s.get("/api/v1/user", &token(&t));
    assert_eq!(
        (r.status, r.msg().as_str()),
        (401, "user does not exist [uid: 0, name: ]")
    );
}

#[test]
fn listener_limits() {
    let s = Srv::start_with(scl_forge::server::Limits {
        max_body: 64,
        ..Default::default()
    });
    let big = json!({"name": "x".repeat(200), "scopes": ["all"]});
    let r = s.post("/api/v1/orgs", &token(&s.admin), big);
    assert_eq!(r.status, 413);
    assert_eq!(s.send("GET", "/nope", None, None).status, 404);
    assert_eq!(
        s.get("/api/v1/user", "garbage").status,
        403,
        "an unparsable header is anonymous"
    );
    let m = s.send("PUT", "/api/v1/user", Some(&token(&s.admin)), None);
    assert_eq!(m.status, 405);
}

#[test]
fn bind_gate_refuses_public_plaintext() {
    use scl_forge::server::bind_gate;
    let lo = "127.0.0.1:3000".parse().unwrap();
    let any = "0.0.0.0:3000".parse().unwrap();
    assert!(bind_gate(&lo, false, false).is_ok());
    assert!(bind_gate(&any, false, false).is_err());
    assert!(bind_gate(&any, true, false).is_ok());
    assert!(bind_gate(&any, false, true).is_ok());
}

#[test]
fn unknown_routes_authenticate_first_and_teams_are_not_served() {
    let s = Srv::start();
    assert_eq!(
        s.send("GET", "/api/v1/repos/x/y", None, None).status,
        403,
        "anonymous learns nothing about the surface"
    );
    assert_eq!(
        s.get("/api/v1/repos/x/y", &token(&"e".repeat(40))).status,
        401
    );
    let r = s.post(
        "/api/v1/orgs/acme/teams",
        &token(&s.admin),
        json!({"name": "devs"}),
    );
    assert_eq!(r.status, 404);
    assert!(r.msg().contains("not"), "{}", r.msg()); // departures.json: teams are out of scope
}

#[test]
fn credentials_cli_forms_parse() {
    let dir = std::env::temp_dir().join(format!("scl-forge-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let bin = env!("CARGO_BIN_EXE_sc-forge");
    let run = |args: &[&str]| {
        let o = std::process::Command::new(bin)
            .args(args)
            .arg("--data-dir")
            .arg(&dir)
            .output()
            .unwrap();
        (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).to_string(),
            String::from_utf8_lossy(&o.stderr).to_string(),
        )
    };
    // Engine's bootstrap passes the flag with `=`.
    let (ok, _, err) = run(&[
        "admin",
        "user",
        "create",
        "--username",
        "eng",
        "--password",
        "pw-eng-1",
        "--email",
        "e@example.invalid",
        "--admin",
        "--must-change-password=false",
    ]);
    assert!(ok, "{err}");
    let (ok, out, err) = run(&[
        "admin",
        "user",
        "generate-access-token",
        "--username",
        "eng",
        "--token-name",
        "t",
        "--scopes",
        "all",
        "--raw",
    ]);
    assert!(ok, "{err}");
    assert_eq!(out.trim().len(), 40, "--raw prints only the token");
    let (ok, _, _) = run(&[
        "admin",
        "user",
        "change-password",
        "--username",
        "eng",
        "--password",
        "pw-eng-2",
        "--must-change-password",
        "false",
    ]);
    assert!(ok);
    assert!(
        !run(&[
            "admin",
            "user",
            "create",
            "--username",
            "eng",
            "--password",
            "x",
            "--email",
            "e@example.invalid"
        ])
        .0,
        "duplicate refuses"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_stalled_request_body_is_cut_off() {
    let s = Srv::start_with(scl_forge::server::Limits {
        body_timeout: std::time::Duration::from_millis(300),
        ..Default::default()
    });
    // Promise 10 bytes, send none: the server must answer 408 instead of holding the connection.
    let head = format!("POST /api/v1/orgs HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: token {}\r\nContent-Length: 10\r\n\r\n", s.admin);
    let r = s.raw(head.as_bytes(), b"");
    assert_eq!(r.status, 408);
}

#[test]
fn token_lists_are_newest_first() {
    let s = Srv::start();
    let pw = s.mk_user("alice");
    for n in ["first", "second", "third"] {
        s.mk_token("alice", &pw, n, &["read:user"]);
    }
    let conn = scl_forge::db::connect(&s.dir).unwrap();
    for (n, t) in [("first", 100), ("second", 200), ("third", 300)] {
        conn.execute(
            "UPDATE tokens SET created_unix = ?1 WHERE name = ?2",
            rusqlite::params![t, n],
        )
        .unwrap();
    }
    let names: Vec<_> = s
        .get("/api/v1/users/alice/tokens", &basic("alice", &pw))
        .json()
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        names,
        ["third", "second", "first"],
        "recorded X#29/R#07 order"
    );
}

#[test]
fn user_and_org_repo_creation_routes_apply_scope_and_actor_rules() {
    let s = Srv::start();
    let adm = token(&s.admin);
    let alice_pw = s.mk_user("alice");
    let bot_pw = s.mk_user("bot");
    let alice_all = s.mk_token("alice", &alice_pw, "all", &["all"]);
    let alice_ro = s.mk_token("alice", &alice_pw, "ro", &["read:repository"]);
    let bot_all = s.mk_token("bot", &bot_pw, "all", &["all"]);
    // R#14: a non-admin creates an organization and becomes its owner.
    let bo = s.post(
        "/api/v1/orgs",
        &token(&bot_all),
        json!({"username": "botorg"}),
    );
    assert_eq!(bo.status, 201);
    // B#26/B#34: scope is checked before the route is served.
    let r = s.post(
        "/api/v1/user/repos",
        &token(&alice_ro),
        json!({"name": "nope"}),
    );
    assert_eq!(
        (r.status, r.msg().as_str()),
        (
            403,
            "token does not have at least one of required scope(s): [write:user]"
        )
    );
    // R#15/R#16: a non-owner is refused whatever the token's scope.
    let wo = s.mk_token("alice", &alice_pw, "wo", &["write:organization"]);
    for t in [&wo, &alice_all] {
        let r = s.post(
            "/api/v1/orgs/botorg/repos",
            &token(t),
            json!({"name": "intruder"}),
        );
        assert_eq!(
            (r.status, r.msg().as_str()),
            (
                403,
                "Given user is not allowed to create repository in organization."
            )
        );
    }
    // The owner and a site admin pass the policy (the handler itself arrives with F2).
    assert_eq!(
        s.post(
            "/api/v1/orgs/botorg/repos",
            &token(&bot_all),
            json!({"name": "legit"})
        )
        .status,
        501
    );
    assert_eq!(
        s.post("/api/v1/orgs/botorg/repos", &adm, json!({"name": "legit"}))
            .status,
        501
    );
    let r = s.post("/api/v1/orgs/ghost/repos", &adm, json!({"name": "x"}));
    assert_eq!(
        (r.status, r.json()["message"].as_str()),
        (404, Some("GetOrgByName"))
    );
    // R#18: a non-owner with a write:organization-only token reads a public org.
    assert_eq!(s.get("/api/v1/orgs/botorg", &token(&wo)).status, 200);
    // R#02: public-only tokens still need the scope.
    let po = s.mk_token(
        "alice",
        &alice_pw,
        "po",
        &["public-only", "read:repository"],
    );
    let r = s.get("/api/v1/user", &token(&po));
    assert_eq!(
        (r.status, r.msg().as_str()),
        (
            403,
            "token does not have at least one of required scope(s): [read:user]"
        )
    );
}

#[test]
fn private_org_permissions_are_hidden_from_outsiders() {
    let s = Srv::start();
    let adm = token(&s.admin);
    let pw = s.mk_user("eve");
    let eve = s.mk_token("eve", &pw, "t", &["read:organization", "read:user"]);
    s.post(
        "/api/v1/orgs",
        &adm,
        json!({"username": "secret", "visibility": "private"}),
    );
    let r = s.get(
        "/api/v1/users/siteadmin/orgs/secret/permissions",
        &token(&eve),
    );
    assert_eq!(
        (r.status, r.msg().as_str()),
        (404, "HasOrgOrUserVisible"),
        "no membership oracle for outsiders"
    );
    assert_eq!(
        s.get("/api/v1/users/siteadmin/orgs/secret/permissions", &adm)
            .status,
        200
    );
}

#[test]
fn admin_lists_another_users_tokens_with_a_password_and_cannot_delete_across_users() {
    let s = Srv::start();
    let alice_pw = s.mk_user("alice");
    let bob_pw = s.mk_user("bob");
    let bob_tok = s.mk_token("bob", &bob_pw, "bobs", &["read:user"]);
    let bobs_id = s
        .get("/api/v1/users/bob/tokens", &basic("bob", &bob_pw))
        .json()[0]["id"]
        .clone();
    // alice cannot reach bob's token through her own path: ids are scoped to the path user.
    let r = s.send(
        "DELETE",
        &format!("/api/v1/users/alice/tokens/{bobs_id}"),
        Some(&basic("alice", &alice_pw)),
        None,
    );
    assert_eq!(r.status, 404);
    assert_eq!(
        s.get("/api/v1/user", &token(&bob_tok)).status,
        200,
        "bob's token survived"
    );
    // X#29: a site admin with a password lists another user's tokens.
    s.post("/api/v1/admin/users", &token(&s.admin), json!({"username": "boss", "email": "b@example.invalid", "password": "boss-pw-1", "must_change_password": false}));
    s.send(
        "PATCH",
        "/api/v1/admin/users/boss",
        Some(&token(&s.admin)),
        Some(&json!({"admin": true})),
    );
    let r = s.get("/api/v1/users/bob/tokens", &basic("boss", "boss-pw-1"));
    assert_eq!((r.status, r.headers["x-total-count"].as_str()), (200, "1"));
}

#[test]
fn password_change_flag_blocks_the_password_but_not_issued_tokens() {
    let s = Srv::start();
    let pw = s.mk_user("alice");
    let t = s.mk_token("alice", &pw, "t", &["read:user"]);
    s.send(
        "PATCH",
        "/api/v1/admin/users/alice",
        Some(&token(&s.admin)),
        Some(&json!({"must_change_password": true})),
    );
    assert_eq!(
        s.post(
            "/api/v1/users/alice/tokens",
            &basic("alice", &pw),
            json!({"name": "n", "scopes": ["all"]})
        )
        .status,
        403
    );
    assert_eq!(s.get("/api/v1/user", &token(&t)).status, 200);
}

#[test]
fn patching_one_field_never_rewrites_another() {
    let s = Srv::start();
    s.mk_user("alice");
    let conn = scl_forge::db::connect(&s.dir).unwrap();
    let alice = scl_forge::store::find_by_login(&conn, "alice")
        .unwrap()
        .unwrap();
    // A stale snapshot of alice, then an admin grant and a password reset land...
    let hash = scl_crypto::hash_password(&scl_crypto::generate_token());
    scl_forge::store::update_user(
        &conn,
        alice.id,
        &scl_forge::store::UserPatch {
            is_admin: Some(true),
            password_hash: Some(hash.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    // ...and a patch that only carries a description must not write the stale flag or hash back.
    scl_forge::store::update_user(
        &conn,
        alice.id,
        &scl_forge::store::UserPatch {
            description: Some("hi".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let now = scl_forge::store::find_by_id(&conn, alice.id)
        .unwrap()
        .unwrap();
    assert_eq!(
        (now.is_admin, now.password_hash, now.description),
        (true, hash, "hi".to_string())
    );
}

#[test]
fn huge_page_numbers_do_not_overflow() {
    let s = Srv::start();
    let r = s.get(
        "/api/v1/admin/users?page=9223372036854775807&limit=50",
        &token(&s.admin),
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!([]));
}

#[test]
fn concurrent_patches_of_different_fields_both_land() {
    let s = Srv::start();
    s.mk_user("alice");
    let id = scl_forge::store::find_by_login(&scl_forge::db::connect(&s.dir).unwrap(), "alice")
        .unwrap()
        .unwrap()
        .id;
    let dir = s.dir.clone();
    let writer = std::thread::spawn(move || {
        let c = scl_forge::db::connect(&dir).unwrap();
        for i in 0..300 {
            let p = scl_forge::store::UserPatch {
                description: Some(format!("d{i}")),
                ..Default::default()
            };
            scl_forge::store::update_user(&c, id, &p).unwrap();
        }
    });
    let c = scl_forge::db::connect(&s.dir).unwrap();
    for _ in 0..300 {
        scl_forge::store::update_user(
            &c,
            id,
            &scl_forge::store::UserPatch {
                is_admin: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
    }
    writer.join().unwrap();
    let u = scl_forge::store::find_by_id(&c, id).unwrap().unwrap();
    assert!(
        u.is_admin,
        "a concurrent description patch must not write a stale is_admin back"
    );
    assert_eq!(u.description, "d299");
}

#[test]
fn login_name_is_stored_by_the_create_itself() {
    let s = Srv::start();
    let r = s.post("/api/v1/admin/users", &token(&s.admin), json!({"username": "lena", "email": "l@example.invalid", "password": "pw", "login_name": "lena-ldap"}));
    assert_eq!(
        (r.status, r.json()["login_name"].as_str()),
        (201, Some("lena-ldap"))
    );
}

#[test]
fn healthz_reports_a_missing_database_and_token_names_may_need_escaping() {
    let s = Srv::start();
    assert_eq!(s.send("GET", "/api/healthz", None, None).status, 200);
    let pw = s.mk_user("alice");
    let basic_alice = basic("alice", &pw);
    s.mk_token("alice", &pw, "release bot", &["read:user"]);
    let del = s.send(
        "DELETE",
        "/api/v1/users/alice/tokens/release%20bot",
        Some(&basic_alice),
        None,
    );
    assert_eq!(
        del.status, 204,
        "an escaped name is decoded before the lookup"
    );
    assert_eq!(
        s.get("/api/v1/users/al%69ce/tokens", &basic_alice).status,
        200,
        "escaped path parameters are decoded"
    );
    assert_eq!(
        s.get("/api/v1/users/%zz/tokens", &token(&s.admin)).status,
        404,
        "malformed escapes match no route"
    );
    // A deleted database must not read as healthy (connect would silently recreate it empty).
    std::fs::remove_file(scl_forge::db::db_path(&s.dir)).unwrap();
    assert_eq!(s.send("GET", "/api/healthz", None, None).status, 503);
}

#[test]
fn a_database_with_the_right_version_but_no_tables_is_not_ready() {
    let s = Srv::start();
    assert_eq!(s.send("GET", "/api/healthz", None, None).status, 200);
    std::fs::remove_file(scl_forge::db::db_path(&s.dir)).unwrap();
    let c = scl_forge::db::connect(&s.dir).unwrap();
    c.pragma_update(None, "user_version", scl_forge::db::SCHEMA_VERSION)
        .unwrap();
    drop(c);
    assert_eq!(
        s.send("GET", "/api/healthz", None, None).status,
        503,
        "version alone does not make a database ready"
    );
}

#[test]
fn serve_refuses_unusable_settings_at_startup() {
    let dir = std::env::temp_dir().join(format!("scl-forge-serve-args-{}", std::process::id()));
    let bin = env!("CARGO_BIN_EXE_sc-forge");
    let run = |extra: &[&str]| {
        std::process::Command::new(bin)
            .args(["serve", "--listen", "127.0.0.1:0", "--data-dir"])
            .arg(&dir)
            .args(extra)
            .output()
            .unwrap()
    };
    let o = run(&[
        "--public-url",
        "http://127.0.0.1:1",
        "--max-connections",
        "0",
    ]);
    assert!(
        !o.status.success() && String::from_utf8_lossy(&o.stderr).contains("--max-connections")
    );
    let o = run(&["--public-url", "http://exämple.com"]);
    assert!(!o.status.success() && String::from_utf8_lossy(&o.stderr).contains("--public-url"));
    let _ = std::fs::remove_dir_all(&dir);
}
