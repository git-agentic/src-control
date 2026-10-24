//! F4c: `kill -9` during merges. A real `sc-forge serve` process merges pull requests while it is
//! killed at an arbitrary moment and restarted; after each restart the merge journal and the
//! reconciler must leave the forge consistent: no pending intent, no receipt ref, and every pull
//! request either wholly merged (its merge commit on the base, two parents) or wholly open (its
//! head not on the base).
#![cfg(unix)]

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sc-forge");
/// Pull requests opened per round.
const PRS: i64 = 4;

struct Server {
    child: Option<Child>,
    port: u16,
}

impl Server {
    fn start(data: &Path, port: u16) -> Server {
        let child = Command::new(BIN)
            .args(["serve", "--data-dir"])
            .arg(data)
            .args([
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--public-url",
                &format!("http://127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start sc-forge");
        let s = Server {
            child: Some(child),
            port,
        };
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(30) {
            if matches!(s.req("GET", "/api/healthz", None, None), Some((200, _))) {
                return s;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("sc-forge did not come up");
    }

    /// SIGKILL: no drain, no cleanup.
    fn kill9(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn req(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Option<(u16, String)> {
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
        let b = body.map(Value::to_string).unwrap_or_default();
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
        if let Some(t) = token {
            head += &format!("Authorization: token {t}\r\n");
        }
        if body.is_some() {
            head += &format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            );
        }
        s.write_all(format!("{head}\r\n{b}").as_bytes()).ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).ok()?;
        let text = String::from_utf8_lossy(&buf).to_string();
        let (h, rest) = text.split_once("\r\n\r\n")?;
        let status = h.split(' ').nth(1)?.parse().ok()?;
        Some((status, rest.to_string()))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.kill9();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn admin(data: &Path, args: &[&str]) -> String {
    let out = Command::new(BIN)
        .arg("admin")
        .args(args)
        .arg("--data-dir")
        .arg(data)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "admin {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn b64(s: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in s.as_bytes().chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            out.push(if i <= c.len() {
                T[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn git(data: &Path, repo: i64, args: &[&str]) -> Option<String> {
    let g = scl_forge::gitproc::Git::new(data, scl_forge::gitproc::find_git().unwrap(), 2).unwrap();
    let dir = data.join("repos").join(format!("{repo}.git"));
    let out = g
        .run(&scl_forge::gitproc::Spec {
            repo: Some(&dir),
            args,
            ..Default::default()
        })
        .unwrap();
    out.ok().then(|| out.text())
}

#[test]
fn kill_nine_during_merges_leaves_a_consistent_forge() {
    let data = std::env::temp_dir().join(format!("scl-forge-crash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    let _tmp = Tmp(data.clone());
    admin(
        &data,
        &[
            "user",
            "create",
            "--username",
            "siteadmin",
            "--password",
            &format!("pw-{}-0123456789", std::process::id()),
            "--email",
            "a@example.invalid",
            "--admin",
            "--must-change-password=false",
        ],
    );
    let tok = admin(
        &data,
        &[
            "user",
            "generate-access-token",
            "--username",
            "siteadmin",
            "--token-name",
            "t",
            "--scopes",
            "all",
            "--raw",
        ],
    );
    let tok = tok.as_str();

    let mut srv = Server::start(&data, free_port());
    let (st, body) = srv
        .req(
            "POST",
            "/api/v1/user/repos",
            Some(tok),
            Some(&json!({"name": "c", "default_branch": "main", "auto_init": true})),
        )
        .unwrap();
    assert_eq!(st, 201, "{body}");
    let repo: i64 = serde_json::from_str::<Value>(&body).unwrap()["id"]
        .as_i64()
        .unwrap();

    // Each round: open fresh pull requests, merge them all at once, kill the server after a delay
    // that lands somewhere inside the merges, restart, and check. The delays sweep the merge's
    // duration (a merge is a dozen git processes, about a second with the durable fsync settings), so some kills hit before the ref transaction,
    // some after it and before the database write.
    let mut total = 0;
    for (round, delay_ms) in [150u64, 500, 900, 1300, 1800].into_iter().enumerate() {
        let first = total + 1;
        for _ in 0..PRS {
            let i = total;
            total += 1;
            let (st, b) = srv
                .req(
                    "POST",
                    &format!("/api/v1/repos/siteadmin/c/contents/m{i}.txt"),
                    Some(tok),
                    Some(&json!({"content": b64("x\n"), "message": format!("m{i}"), "branch": "main", "new_branch": format!("b{i}")})),
                )
                .unwrap();
            assert_eq!(st, 201, "round {round}: {b}");
            let (st, b) = srv
                .req(
                    "POST",
                    "/api/v1/repos/siteadmin/c/pulls",
                    Some(tok),
                    Some(&json!({"title": format!("PR {i}"), "head": format!("b{i}"), "base": "main"})),
                )
                .unwrap();
            assert_eq!(st, 201, "round {round}: {b}");
        }
        let port = srv.port;
        std::thread::scope(|sc| {
            for n in first..=total {
                sc.spawn(move || {
                    let c = Server { child: None, port };
                    let _ = c.req(
                        "POST",
                        &format!("/api/v1/repos/siteadmin/c/pulls/{n}/merge"),
                        Some(tok),
                        Some(&json!({"Do": "merge"})),
                    );
                });
            }
            std::thread::sleep(Duration::from_millis(delay_ms));
            srv.kill9();
        });
        // restart: `serve` repairs the journal before it accepts anything
        srv = Server::start(&data, free_port());
        check(&srv, tok, &data, repo, total);
    }

    // whatever is still open merges normally now
    for n in 1..=total {
        let (_, b) = srv
            .req(
                "GET",
                &format!("/api/v1/repos/siteadmin/c/pulls/{n}"),
                Some(tok),
                None,
            )
            .unwrap();
        if serde_json::from_str::<Value>(&b).unwrap()["merged"] != json!(true) {
            let (st, b) = srv
                .req(
                    "POST",
                    &format!("/api/v1/repos/siteadmin/c/pulls/{n}/merge"),
                    Some(tok),
                    Some(&json!({"Do": "merge"})),
                )
                .unwrap();
            assert!(st == 200 || st == 405, "{st}: {b}");
        }
    }
    check(&srv, tok, &data, repo, total);
    for i in 0..total {
        assert!(
            git(
                &data,
                repo,
                &["cat-file", "-e", &format!("refs/heads/main:m{i}.txt")]
            )
            .is_some(),
            "m{i}.txt is on main at the end"
        );
    }
}

/// The invariants after a restart.
fn check(srv: &Server, tok: &str, data: &Path, repo: i64, total: i64) {
    let conn = scl_forge::db::connect(data).unwrap();
    assert!(
        !scl_forge::merges::has_pending(&conn, repo),
        "a pending intent survived the restart"
    );
    assert_eq!(
        git(data, repo, &["for-each-ref", "refs/forge/merge"]).unwrap(),
        "",
        "a receipt survived the restart"
    );
    let main = git(data, repo, &["rev-parse", "refs/heads/main"]).unwrap();
    let mut merged = 0;
    let aborted: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM merge_intents WHERE state = 'aborted'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    for n in 1..=total {
        let (st, b) = srv
            .req(
                "GET",
                &format!("/api/v1/repos/siteadmin/c/pulls/{n}"),
                Some(tok),
                None,
            )
            .unwrap();
        assert_eq!(st, 200, "{b}");
        let pr: Value = serde_json::from_str(&b).unwrap();
        let head = git(
            data,
            repo,
            &["rev-parse", &format!("refs/heads/b{}", n - 1)],
        )
        .unwrap();
        let on_main = git(data, repo, &["merge-base", "--is-ancestor", &head, &main]).is_some();
        let file_on_main = git(
            data,
            repo,
            &["cat-file", "-e", &format!("{main}:m{}.txt", n - 1)],
        )
        .is_some();
        if pr["merged"] == json!(true) {
            merged += 1;
            let m = pr["merge_commit_sha"].as_str().unwrap();
            assert_eq!(
                git(data, repo, &["rev-list", "--parents", "-n", "1", m])
                    .unwrap()
                    .split(' ')
                    .count(),
                3,
                "PR {n}: a merge commit has two parents"
            );
            assert!(
                on_main && file_on_main,
                "PR {n} is merged, so its commits are on main"
            );
            assert_eq!(pr["head"]["sha"], head.as_str());
        } else {
            assert!(
                !on_main && !file_on_main,
                "PR {n} is open but its head is already on main (a landed merge was not finalized)"
            );
        }
    }
    eprintln!("after the restart: {merged} of {total} merged, {aborted} intents aborted so far");
}
