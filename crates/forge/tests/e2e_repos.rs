//! F2a: repositories, listings, collaborators, branches, over a real socket. The recorded
//! exchanges that need no later slice are also replayed by `forge-check.sh`; these tests add the
//! negative and cross-cutting cases the recordings do not cover.
#![cfg(unix)]

mod common;
use common::*;
use serde_json::{json, Value};

fn fixture_keys(file: &str, exchange: usize) -> Vec<String> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("conformance/fixtures/1.22.6")
        .join(file);
    let v: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    v["exchanges"][exchange]["body"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

struct World {
    s: Srv,
    adm: String,
}

/// acme (private org owned by siteadmin) plus users alice (owner of nothing), bob, carol, dave
/// each with an all-scope token.
fn world() -> (World, std::collections::HashMap<&'static str, String>) {
    let s = Srv::start();
    let adm = token(&s.admin);
    assert_eq!(
        s.post(
            "/api/v1/orgs",
            &adm,
            json!({"username": "acme", "visibility": "private"})
        )
        .status,
        201
    );
    let mut t = std::collections::HashMap::new();
    for u in ["alice", "bob", "carol", "dave"] {
        let pw = s.mk_user(u);
        t.insert(u, s.mk_token(u, &pw, "all", &["all"]));
    }
    (World { s, adm }, t)
}

impl World {
    fn mk(&self, name: &str, init: bool) -> Value {
        let r = self.s.post(
            "/api/v1/orgs/acme/repos",
            &self.adm,
            json!({"name": name, "auto_init": init, "private": true}),
        );
        assert_eq!(r.status, 201, "{}", r.msg());
        r.json()
    }
    fn collab(&self, repo: &str, user: &str, mode: &str) {
        let r = self.s.send(
            "PUT",
            &format!("/api/v1/repos/acme/{repo}/collaborators/{user}"),
            Some(&self.adm),
            Some(&json!({"permission": mode})),
        );
        assert_eq!(r.status, 204, "{}", r.msg());
    }
}

#[test]
fn create_get_patch_delete_round_trip_and_the_recorded_object_shape() {
    let (w, _) = world();
    let r = w.mk("alpha", true);
    let want = fixture_keys("C-repos.json", 0);
    for k in &want {
        assert!(r.get(k).is_some(), "repo object lacks recorded key {k}");
    }
    assert_eq!(
        (
            r["full_name"].as_str(),
            r["private"].as_bool(),
            r["empty"].as_bool(),
            r["default_branch"].as_str()
        ),
        (Some("acme/alpha"), Some(true), Some(false), Some("main"))
    );
    assert_eq!(
        r["permissions"],
        json!({"admin": true, "push": true, "pull": true})
    );
    // an empty repo reads empty, with the requested default branch
    let e =
        w.s.post(
            "/api/v1/orgs/acme/repos",
            &w.adm,
            json!({"name": "blank", "auto_init": false, "default_branch": "trunk"}),
        )
        .json();
    assert_eq!(
        (e["empty"].as_bool(), e["default_branch"].as_str()),
        (Some(true), Some("trunk"))
    );

    // PATCH: description and website land; private:false is accepted and stays true; has_* ignored
    let p = w.s.send("PATCH", "/api/v1/repos/acme/alpha", Some(&w.adm), Some(&json!({"description": "A", "website": "https://x.invalid", "private": false, "has_actions": true})));
    assert_eq!(p.status, 200);
    assert_eq!(
        (
            p.json()["description"].as_str(),
            p.json()["website"].as_str(),
            p.json()["private"].as_bool(),
            p.json()["has_actions"].as_bool()
        ),
        (
            Some("A"),
            Some("https://x.invalid"),
            Some(true),
            Some(false)
        )
    );
    // rename is refused, naming the same name is a no-op, a missing default branch is 422
    let rn = w.s.send(
        "PATCH",
        "/api/v1/repos/acme/alpha",
        Some(&w.adm),
        Some(&json!({"name": "renamed"})),
    );
    assert_eq!(
        (rn.status, rn.msg().as_str()),
        (422, "repository rename is not supported")
    );
    assert_eq!(
        w.s.send(
            "PATCH",
            "/api/v1/repos/acme/alpha",
            Some(&w.adm),
            Some(&json!({"name": "alpha"}))
        )
        .status,
        200
    );
    let nb = w.s.send(
        "PATCH",
        "/api/v1/repos/acme/alpha",
        Some(&w.adm),
        Some(&json!({"default_branch": "nope"})),
    );
    assert_eq!(
        (nb.status, nb.msg().as_str()),
        (422, "branch does not exist [name: nope]")
    );
    let rev = w.s.send(
        "PATCH",
        "/api/v1/repos/acme/alpha",
        Some(&w.adm),
        Some(&json!({"default_branch": "main~1"})),
    );
    assert_eq!(rev.status, 422, "a revision is not a branch name");

    // delete, then the name is free and a recreate is a different repository
    let id = r["id"].as_i64().unwrap();
    assert_eq!(
        w.s.send("DELETE", "/api/v1/repos/acme/alpha", Some(&w.adm), None)
            .status,
        204
    );
    assert_eq!(w.s.get("/api/v1/repos/acme/alpha", &w.adm).status, 404);
    assert_eq!(
        w.s.send("DELETE", "/api/v1/repos/acme/alpha", Some(&w.adm), None)
            .status,
        404
    );
    assert!(!w.s.dir.join("repos").join(format!("{id}.git")).exists());
    let again = w.mk("alpha", true);
    assert_ne!(again["id"].as_i64().unwrap(), id);
}

#[test]
fn names_follow_the_recorded_rules_and_are_unique_in_any_case() {
    let (w, _) = world();
    w.mk("Mixed", false);
    for dup in ["mixed", "MIXED"] {
        let d =
            w.s.post("/api/v1/orgs/acme/repos", &w.adm, json!({"name": dup}));
        assert_eq!(
            (d.status, d.msg().as_str()),
            (409, "The repository with the same name already exists."),
            "{dup}"
        );
    }
    for case in [
        "/repos/acme/mixed",
        "/repos/acme/Mixed",
        "/repos/ACME/mixed",
    ] {
        assert_eq!(
            w.s.get(&format!("/api/v1{case}"), &w.adm).json()["name"],
            "Mixed",
            "{case}"
        );
    }
    for (name, status, msg) in [
        (".", 422, "name is reserved [name: .]"),
        ("..", 422, "name is reserved [name: ..]"),
        (
            "trail.git",
            422,
            "name pattern is not allowed [pattern: *.git]",
        ),
        ("a b", 422, "[Name]: AlphaDashDot"),
        ("", 422, "[Name]: Required"),
        (".hidden", 201, ""),
        ("-dash", 201, ""),
        ("a..b", 201, ""),
        ("api", 201, ""),
    ] {
        let r =
            w.s.post("/api/v1/orgs/acme/repos", &w.adm, json!({"name": name}));
        assert_eq!(r.status, status, "{name}");
        if status != 201 {
            assert_eq!(r.msg(), msg, "{name}");
        }
    }
    let long = w.s.post(
        "/api/v1/orgs/acme/repos",
        &w.adm,
        json!({"name": "x".repeat(101)}),
    );
    assert_eq!(long.msg(), "[Name]: MaxSize");
    let bad = w.s.post(
        "/api/v1/orgs/acme/repos",
        &w.adm,
        json!({"name": "ok", "default_branch": "a..b"}),
    );
    assert_eq!(bad.status, 422);
}

#[test]
fn a_foreign_token_gets_what_a_missing_repo_gets() {
    let (w, t) = world();
    w.mk("secret", false);
    let foreign = w.s.get("/api/v1/repos/acme/secret", &token(&t["dave"]));
    let missing = w.s.get("/api/v1/repos/acme/ghost", &token(&t["dave"]));
    assert_eq!(
        (foreign.status, &foreign.raw),
        (404, &missing.raw),
        "no existence oracle"
    );
    for path in ["/branches", "/branches/main", "/collaborators"] {
        let a = w.s.get(
            &format!("/api/v1/repos/acme/secret{path}"),
            &token(&t["dave"]),
        );
        let b = w.s.get(
            &format!("/api/v1/repos/acme/ghost{path}"),
            &token(&t["dave"]),
        );
        assert_eq!((a.status, &a.raw), (404, &b.raw), "{path}");
    }
    assert_eq!(
        w.s.send(
            "DELETE",
            "/api/v1/repos/acme/secret",
            Some(&token(&t["dave"])),
            None
        )
        .status,
        404
    );
    assert_eq!(
        w.s.send(
            "PATCH",
            "/api/v1/repos/acme/secret",
            Some(&token(&t["dave"])),
            Some(&json!({}))
        )
        .status,
        404
    );
}

#[test]
fn collaborator_modes_limit_what_each_can_do() {
    let (w, t) = world();
    w.mk("r", true);
    w.collab("r", "bob", "read");
    w.collab("r", "carol", "write");
    w.collab("r", "alice", "admin");
    let call = |who: &str, method: &str, path: &str, body: Option<Value>| {
        w.s.send(
            method,
            &format!("/api/v1{path}"),
            Some(&token(&t[who])),
            body.as_ref(),
        )
        .status
    };
    // read: can read, cannot write anything
    assert_eq!(call("bob", "GET", "/repos/acme/r", None), 200);
    assert_eq!(
        w.s.get("/api/v1/repos/acme/r", &token(&t["bob"])).json()["permissions"],
        json!({"admin": false, "push": false, "pull": true})
    );
    for (m, p) in [
        ("PATCH", "/repos/acme/r"),
        ("DELETE", "/repos/acme/r"),
        ("PUT", "/repos/acme/r/collaborators/dave"),
        ("GET", "/repos/acme/r/collaborators"),
        ("DELETE", "/repos/acme/r/branches/x"),
    ] {
        assert_eq!(call("bob", m, p, Some(json!({}))), 403, "read {m} {p}");
    }
    // write: can delete branches, still cannot administer
    assert_eq!(
        w.s.get("/api/v1/repos/acme/r", &token(&t["carol"])).json()["permissions"],
        json!({"admin": false, "push": true, "pull": true})
    );
    for (m, p) in [
        ("PATCH", "/repos/acme/r"),
        ("DELETE", "/repos/acme/r"),
        ("PUT", "/repos/acme/r/collaborators/dave"),
    ] {
        assert_eq!(call("carol", m, p, Some(json!({}))), 403, "write {m} {p}");
    }
    // admin collaborator: administers, may grant admin, but cannot delete the repository
    assert_eq!(
        call(
            "alice",
            "PATCH",
            "/repos/acme/r",
            Some(json!({"description": "x"}))
        ),
        200
    );
    assert_eq!(
        call(
            "alice",
            "PUT",
            "/repos/acme/r/collaborators/dave",
            Some(json!({"permission": "admin"}))
        ),
        204
    );
    assert_eq!(
        call("alice", "DELETE", "/repos/acme/r", None),
        403,
        "only owner-level may delete"
    );
    // the new admin (dave) is in the listing in insertion order, and removal works
    let names: Vec<String> =
        w.s.get("/api/v1/repos/acme/r/collaborators", &w.adm)
            .json()
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["login"].as_str().unwrap().into())
            .collect();
    assert_eq!(names, ["bob", "carol", "alice", "dave"]);
    assert_eq!(
        call("alice", "DELETE", "/repos/acme/r/collaborators/dave", None),
        204
    );
    assert_eq!(
        call("dave", "GET", "/repos/acme/r", None),
        404,
        "removed: invisible again"
    );
}

#[test]
fn collaborator_edge_cases() {
    let (w, _) = world();
    w.mk("r", false);
    let put = |u: &str, body: Value| {
        w.s.send(
            "PUT",
            &format!("/api/v1/repos/acme/r/collaborators/{u}"),
            Some(&w.adm),
            Some(&body),
        )
    };
    let r = put("nobody-here", json!({"permission": "write"}));
    assert_eq!(
        (r.status, r.msg().as_str()),
        (422, "user does not exist [uid: 0, name: nobody-here]")
    );
    let r = put("acme", json!({}));
    assert_eq!(
        (r.status, r.msg().as_str()),
        (422, "user does not exist [uid: 0, name: acme]"),
        "an organization is not a collaborator"
    );
    assert_eq!(
        put("siteadmin", json!({})).status,
        422,
        "the owner (org owner) cannot be added"
    );
    assert_eq!(put("bob", json!({"permission": "superuser"})).status, 422);
    assert_eq!(
        put("bob", json!({})).status,
        204,
        "write is the default mode"
    );
    let perm =
        w.s.get("/api/v1/repos/acme/r/collaborators/bob/permission", &w.adm)
            .json();
    assert_eq!(
        (
            perm["permission"].as_str(),
            perm["role_name"].as_str(),
            perm["user"]["login"].as_str()
        ),
        (Some("write"), Some("write"), Some("bob"))
    );
    assert_eq!(
        w.s.get(
            "/api/v1/repos/acme/r/collaborators/siteadmin/permission",
            &w.adm
        )
        .json()["permission"],
        "owner"
    );
    assert_eq!(
        w.s.get(
            "/api/v1/repos/acme/r/collaborators/carol/permission",
            &w.adm
        )
        .json()["permission"],
        "none"
    );
}

#[test]
fn a_public_only_token_sees_and_creates_nothing() {
    let (w, _) = world();
    w.mk("r", false);
    let pw = w.s.mk_user("pat");
    let po = token(&w.s.mk_token(
        "pat",
        &pw,
        "po",
        &[
            "public-only",
            "read:repository",
            "write:user",
            "read:user",
            "write:organization",
        ],
    ));
    let r = w.s.get("/api/v1/repos/acme/r", &po);
    assert_eq!(
        (r.status, r.msg().as_str()),
        (403, "token scope is limited to public repos")
    );
    let r = w.s.get("/api/v1/repos/acme/ghost", &po);
    assert_eq!(r.status, 403, "refused before existence is looked at");
    for path in [
        "/api/v1/repos/search?limit=50",
        "/api/v1/user/repos",
        "/api/v1/orgs/acme/repos",
    ] {
        let l = w.s.get(path, &po);
        assert_eq!(l.status, 200, "{path}");
        assert_eq!(l.headers["x-total-count"], "0", "{path}");
    }
    assert_eq!(
        w.s.get("/api/v1/repos/search", &po).json(),
        json!({"ok": true, "data": []})
    );
    let c = w.s.post("/api/v1/user/repos", &po, json!({"name": "mine"}));
    assert_eq!(
        (c.status, c.msg().as_str()),
        (403, "token scope is limited to public repos")
    );
}

#[test]
fn listings_are_filtered_by_access_with_visible_counts() {
    let (w, t) = world();
    for n in ["a1", "a2", "a3"] {
        w.mk(n, false);
    }
    w.collab("a2", "bob", "read");
    let list = |tok: &str, path: &str| {
        let r = w.s.get(path, &token(tok));
        let v = r.json();
        let items = v.get("data").cloned().unwrap_or(v);
        (
            items
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x["full_name"].as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
            r.headers.get("x-total-count").cloned().unwrap(),
        )
    };
    assert_eq!(
        list(&t["bob"], "/api/v1/repos/search?limit=50&sort=alpha"),
        (vec!["acme/a2".to_string()], "1".to_string())
    );
    assert_eq!(
        list(&t["dave"], "/api/v1/repos/search"),
        (vec![], "0".to_string())
    );
    assert_eq!(
        list(&t["bob"], "/api/v1/user/repos"),
        (vec!["acme/a2".to_string()], "1".to_string())
    );
    // an invisible org still answers 200 with only what the caller can read (recorded K#55)
    assert_eq!(
        list(&t["bob"], "/api/v1/orgs/acme/repos"),
        (vec!["acme/a2".to_string()], "1".to_string())
    );
    assert_eq!(
        list(&t["dave"], "/api/v1/orgs/acme/repos"),
        (vec![], "0".to_string())
    );
    assert_eq!(
        w.s.get("/api/v1/orgs/ghost/repos", &token(&t["bob"]))
            .status,
        404
    );
    // the admin sees all three, paging keeps the total, q filters
    let all =
        w.s.get("/api/v1/repos/search?limit=2&page=2&sort=alpha", &w.adm);
    assert_eq!(
        (
            all.json()["data"].as_array().unwrap().len(),
            all.headers["x-total-count"].as_str()
        ),
        (1, "3")
    );
    assert_eq!(
        list(&w.s.admin, "/api/v1/repos/search?q=A2").0,
        vec!["acme/a2".to_string()]
    );
}

#[test]
fn branches_are_listed_fetched_and_deleted_with_slashes_in_their_names() {
    let (w, t) = world();
    let r = w.mk("br", false);
    let id = r["id"].as_i64().unwrap();
    let empty = w.s.get("/api/v1/repos/acme/br/branches", &w.adm);
    assert_eq!(
        (empty.status, empty.json()),
        (200, Value::Null),
        "recorded: an empty repo lists null"
    );
    let main = w.s.commit_on(id, "main", None);
    w.s.commit_on(id, "feat/x", Some(&main));
    let list = w.s.get("/api/v1/repos/acme/br/branches", &w.adm);
    let names: Vec<&str> = list
        .json()
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect::<Vec<_>>()
        .into_iter()
        .map(|s| Box::leak(s.to_string().into_boxed_str()) as &str)
        .collect();
    assert_eq!(names, ["feat/x", "main"]);
    assert_eq!(list.headers["x-total-count"], "2");
    let b =
        w.s.get("/api/v1/repos/acme/br/branches/feat/x", &w.adm)
            .json();
    assert_eq!(b["name"], "feat/x");
    assert_eq!(b["commit"]["message"], "msg\n");
    assert_eq!(b["commit"]["author"]["email"], "t@example.invalid");
    for k in [
        "protected",
        "required_approvals",
        "enable_status_check",
        "status_check_contexts",
        "user_can_push",
        "user_can_merge",
        "effective_branch_protection_name",
    ] {
        assert!(b.get(k).is_some(), "{k}");
    }
    let nope = w.s.get("/api/v1/repos/acme/br/branches/nope", &w.adm);
    assert_eq!(
        (nope.status, nope.json()["errors"][0].as_str()),
        (404, Some("branch does not exist [name: nope]"))
    );
    assert_eq!(
        w.s.get("/api/v1/repos/acme/br/branches/main~1", &w.adm)
            .status,
        404,
        "never resolved as a revision"
    );
    // delete: the default branch stays (403), others go (204), then 404
    let d = w.s.send(
        "DELETE",
        "/api/v1/repos/acme/br/branches/main",
        Some(&w.adm),
        None,
    );
    assert_eq!(
        (d.status, d.msg().as_str()),
        (403, "can not delete default branch")
    );
    assert_eq!(
        w.s.send(
            "DELETE",
            "/api/v1/repos/acme/br/branches/feat/x",
            Some(&w.adm),
            None
        )
        .status,
        204
    );
    assert_eq!(
        w.s.send(
            "DELETE",
            "/api/v1/repos/acme/br/branches/feat/x",
            Some(&w.adm),
            None
        )
        .status,
        404
    );
    // a read collaborator cannot delete branches
    w.collab("br", "bob", "read");
    assert_eq!(
        w.s.send(
            "DELETE",
            "/api/v1/repos/acme/br/branches/main",
            Some(&token(&t["bob"])),
            None
        )
        .status,
        403
    );
    // changing the default branch works once the branch exists
    w.s.commit_on(id, "dev", Some(&main));
    let p = w.s.send(
        "PATCH",
        "/api/v1/repos/acme/br",
        Some(&w.adm),
        Some(&json!({"default_branch": "dev"})),
    );
    assert_eq!(
        (p.status, p.json()["default_branch"].as_str()),
        (200, Some("dev"))
    );
    assert_eq!(
        w.s.git(id, &["symbolic-ref", "HEAD"], None),
        "refs/heads/dev"
    );
}

#[test]
fn every_token_form_authenticates_on_a_repo_route_and_a_password_does_not() {
    let (w, t) = world();
    w.mk("authrepo", true);
    w.collab("authrepo", "bob", "write");
    let tok = &t["bob"];
    for (label, auth) in [
        ("token", token(tok)),
        ("Bearer", format!("Bearer {tok}")),
        ("basic token password", basic("bob", tok)),
        ("basic token user", basic(tok, "")),
        ("basic oauth2", basic("oauth2", tok)),
        ("basic other name", basic("someone", tok)),
    ] {
        let r = w.s.get("/api/v1/repos/acme/authrepo", &auth);
        assert_eq!(
            (r.status, r.json()["full_name"].as_str()),
            (200, Some("acme/authrepo")),
            "{label}"
        );
    }
    let bad = w.s.get(
        "/api/v1/repos/acme/authrepo",
        &format!("Bearer {}", "e".repeat(40)),
    );
    assert_eq!(
        (bad.status, bad.msg().as_str()),
        (401, "user does not exist [uid: 0, name: ]")
    );
    assert_eq!(
        w.s.send("GET", "/api/v1/repos/acme/authrepo", None, None)
            .status,
        403
    );
    assert_eq!(
        w.s.get(
            "/api/v1/repos/acme/authrepo",
            &basic("bob", "pw-bob-0123456789")
        )
        .status,
        401,
        "a password never authenticates an ordinary route"
    );
}

#[test]
fn org_and_user_repo_creation_respect_ownership() {
    let (w, t) = world();
    // alice owns user repos; a non-owner cannot create in acme; an org owner can
    let r = w.s.post(
        "/api/v1/user/repos",
        &token(&t["alice"]),
        json!({"name": "mine", "auto_init": true}),
    );
    assert_eq!(
        (
            r.status,
            r.json()["full_name"].as_str(),
            r.json()["owner"]["login"].as_str()
        ),
        (201, Some("alice/mine"), Some("alice"))
    );
    let own = w.s.get("/api/v1/user/repos", &token(&t["alice"]));
    assert_eq!(own.headers["x-total-count"], "1");
    let no = w.s.post(
        "/api/v1/orgs/acme/repos",
        &token(&t["alice"]),
        json!({"name": "intruder"}),
    );
    assert_eq!(
        no.status, 404,
        "acme is private: a non-owner cannot even tell it exists"
    );
    // another user cannot read alice's repo, the site admin can
    assert_eq!(
        w.s.get("/api/v1/repos/alice/mine", &token(&t["bob"]))
            .status,
        404
    );
    assert_eq!(w.s.get("/api/v1/repos/alice/mine", &w.adm).status, 200);
    // the initial commit is authored by the creating user
    let id = r.json()["id"].as_i64().unwrap();
    assert_eq!(
        w.s.git(id, &["log", "-1", "--format=%an|%ae", "main"], None),
        "alice|alice@example.invalid"
    );
}

#[test]
fn concurrent_creates_of_one_name_yield_exactly_one_repository() {
    let (w, _) = world();
    let (s, adm) = (&w.s, &w.adm);
    let results: Vec<u16> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..6)
            .map(|_| {
                sc.spawn(|| {
                    s.post(
                        "/api/v1/orgs/acme/repos",
                        adm,
                        json!({"name": "race", "auto_init": true}),
                    )
                    .status
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(
        results.iter().filter(|c| **c == 201).count(),
        1,
        "{results:?}"
    );
    assert!(
        results.iter().all(|c| *c == 201 || *c == 409),
        "{results:?}"
    );
    let dirs = std::fs::read_dir(w.s.dir.join("repos")).unwrap().count();
    assert_eq!(dirs, 1, "no leftover directory from the losers");
}

#[test]
fn deleting_a_repo_while_requests_are_in_flight_leaves_nothing_behind() {
    let (w, _) = world();
    let r = w.mk("gone", true);
    let id = r["id"].as_i64().unwrap();
    let (s, adm) = (&w.s, &w.adm);
    std::thread::scope(|sc| {
        let readers: Vec<_> = (0..4)
            .map(|_| {
                sc.spawn(|| {
                    (0..10)
                        .map(|_| s.get("/api/v1/repos/acme/gone/branches", adm).status)
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert_eq!(
            s.send("DELETE", "/api/v1/repos/acme/gone", Some(adm), None)
                .status,
            204
        );
        for h in readers {
            for st in h.join().unwrap() {
                assert!(
                    st == 200 || st == 404,
                    "reads see the repo or its absence, never an error: {st}"
                );
            }
        }
    });
    assert!(!w.s.dir.join("repos").join(format!("{id}.git")).exists());
    assert!(!w.s.dir.join("trash").join(format!("{id}.git")).exists());
}
