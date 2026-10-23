//! Every route the recorded fixtures exercise inside the F1 surface must resolve
//! to a declared row, and the declared rows carry a policy. A new fixture route
//! that is neither declared nor listed as a later slice fails here.
#![cfg(unix)]

use scl_forge::routes::{resolve, Class, ROUTES};
use serde_json::Value;

/// Paths a later slice owns (repos, git, teams are out of scope entirely).
fn later(path: &str) -> bool {
    path.starts_with("/repos/")
        || path.starts_with("/user/repos")
        || path.starts_with("/teams/")
        || path.ends_with("/teams")
        || (path.starts_with("/orgs/") && path.ends_with("/repos") && !path.starts_with("/orgs/{"))
}

fn concretize(path: &str) -> String {
    // Fixture placeholders -> plain segments; the router only looks at shape.
    let mut out = String::new();
    let mut rest = path;
    while let Some(i) = rest.find('<') {
        out.push_str(&rest[..i]);
        let j = rest[i..].find('>').map(|k| i + k + 1).unwrap_or(rest.len());
        out.push('x');
        rest = &rest[j..];
    }
    out.push_str(rest);
    out
}

#[test]
fn fixture_routes_in_the_f1_surface_are_declared() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance/fixtures/1.22.6");
    let mut checked = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().is_none_or(|e| e != "json") || p.file_name().unwrap() == "meta.json" {
            continue;
        }
        let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        for ex in v["exchanges"].as_array().unwrap() {
            if ex["kind"] != "http" || ex["method"].is_null() {
                continue;
            }
            let full = concretize(ex["path"].as_str().unwrap());
            let Some(path) = full.strip_prefix("/api/v1") else {
                continue;
            };
            let path = path.split('?').next().unwrap();
            if later(path) || path == "/healthz" || path.starts_with("/repos") {
                continue;
            }
            let method = ex["method"].as_str().unwrap();
            assert!(
                resolve(method, path).is_ok(),
                "{method} {path} ({}) has no route row",
                p.display()
            );
            checked.insert(format!("{method} {path}"));
        }
    }
    assert!(
        checked.len() >= 10,
        "the fixtures should exercise many F1 routes, saw {checked:?}"
    );
}

#[test]
fn token_routes_are_exactly_the_password_routes() {
    let mut pw: Vec<_> = ROUTES
        .iter()
        .filter(|r| r.class == Class::Password)
        .map(|r| r.pattern)
        .collect();
    pw.sort();
    assert_eq!(
        pw,
        [
            "/users/{u}/tokens",
            "/users/{u}/tokens",
            "/users/{u}/tokens/{id}"
        ]
    );
    for r in ROUTES.iter().filter(|r| r.class == Class::Password) {
        assert!(
            r.need.is_none(),
            "password auth carries full scope; a scope rule here would be dead code"
        );
    }
    for r in ROUTES
        .iter()
        .filter(|r| r.class == Class::Token && r.pattern != "/version")
    {
        assert!(
            r.need.is_some(),
            "{} {} must declare a scope",
            r.method,
            r.pattern
        );
    }
}
