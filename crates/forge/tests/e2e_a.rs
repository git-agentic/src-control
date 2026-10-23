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
    assert_eq!(l.json()[0]["name"], "ci");
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
fn wrong_passwords_are_indistinguishable_and_unknown_users_cost_the_same() {
    let s = Srv::start();
    let pw = s.mk_user("alice");
    let wrong = s.post(
        "/api/v1/users/alice/tokens",
        &basic("alice", "nope"),
        json!({"name": "a", "scopes": ["all"]}),
    );
    let unknown = s.post(
        "/api/v1/users/nobody/tokens",
        &basic("nobody", "nope"),
        json!({"name": "a", "scopes": ["all"]}),
    );
    assert_eq!((wrong.status, unknown.status), (401, 401));
    assert_eq!(wrong.raw, unknown.raw, "same body: no account enumeration");
    // The right password still works straight after failures (backoff is not a lockout).
    assert_eq!(
        s.post(
            "/api/v1/users/alice/tokens",
            &basic("alice", &pw),
            json!({"name": "ok", "scopes": ["all"]})
        )
        .status,
        201
    );
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
    scl_forge::admin::user_create(
        &s.dir,
        "carol",
        "carol-pw-1",
        "c@example.invalid",
        false,
        false,
    )
    .unwrap();
    let t = scl_forge::admin::generate_access_token(&s.dir, "carol", "cli", &["read:user".into()])
        .unwrap();
    assert_eq!(s.get("/api/v1/user", &token(&t)).json()["login"], "carol");
    scl_forge::admin::user_change_password(&s.dir, "carol", "carol-pw-2", false).unwrap();
    assert_eq!(
        s.post(
            "/api/v1/users/carol/tokens",
            &basic("carol", "carol-pw-1"),
            json!({"name": "o", "scopes": ["all"]})
        )
        .status,
        401
    );
    assert_eq!(
        s.post(
            "/api/v1/users/carol/tokens",
            &basic("carol", "carol-pw-2"),
            json!({"name": "n", "scopes": ["all"]})
        )
        .status,
        201
    );
    scl_forge::admin::org_create(&s.dir, "cliorg", "carol").unwrap();
    assert_eq!(s.get("/api/v1/orgs/cliorg", &token(&s.admin)).status, 200);
    assert!(
        scl_forge::admin::user_create(&s.dir, "carol", "x", "c@example.invalid", false, false)
            .is_err()
    );
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
