//! F5b: the operating surface of a real `sc-forge serve` process: the SIGTERM drain, the bind
//! gate and the log lines.
#![cfg(unix)]

use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sc-forge");

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp(tag: &str) -> Tmp {
    let d = std::env::temp_dir().join(format!("scl-forge-ops-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Tmp(d)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Proc {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl Proc {
    /// Start `serve` on a free loopback port with `extra` flags and wait for `/healthz`.
    fn start(root: &Path, extra: &[&str]) -> Proc {
        let data = root.join("data");
        let port = free_port();
        let log = root.join("stderr.log");
        let child = Command::new(BIN)
            .args(["serve", "--data-dir"])
            .arg(&data)
            .args([
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--public-url",
                &format!("http://127.0.0.1:{port}"),
            ])
            .args(extra)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .expect("start sc-forge");
        let p = Proc { child, port, log };
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(30) {
            if p.get("/api/healthz", None).is_some_and(|(s, _)| s == 200) {
                return p;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("sc-forge did not come up: {}", p.stderr());
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn get(&self, path: &str, token: Option<&str>) -> Option<(u16, String)> {
        self.send("GET", path, token, None)
    }

    fn send(
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
        Some((h.split(' ').nth(1)?.parse().ok()?, rest.to_string()))
    }

    fn sigterm(&self) {
        // SAFETY: SIGTERM to the server this test spawned.
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
    }

    /// Wait for the process to exit, at most `limit`.
    fn wait(&mut self, limit: Duration) -> Option<ExitStatus> {
        let t0 = Instant::now();
        while t0.elapsed() < limit {
            if let Ok(Some(st)) = self.child.try_wait() {
                return Some(st);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Create the site admin (as Engine's bootstrap does) and return an all-scope token.
fn bootstrap(root: &Path) -> String {
    let data = root.join("data");
    scl_forge::admin::user_create(
        &data,
        "siteadmin",
        &scl_crypto::generate_token(),
        "admin@example.invalid",
        true,
        false,
    )
    .unwrap();
    scl_forge::admin::generate_access_token(&data, "siteadmin", "boot", &["all".to_string()])
        .unwrap()
}

#[test]
fn sigterm_closes_idle_connections_refuses_new_ones_and_exits_zero() {
    let root = tmp("idle");
    let mut p = Proc::start(&root.0, &[]);
    // A keep-alive client that went idle after its request.
    let mut idle = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
    idle.write_all(b"GET /api/healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 1024];
    assert!(idle.read(&mut buf).unwrap() > 0, "the first response");
    p.sigterm();
    // Closed by the server at once, not after the drain deadline (30 s by default).
    let t0 = Instant::now();
    let mut rest = Vec::new();
    let _ = idle.read_to_end(&mut rest);
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "an idle keep-alive connection must not hold the drain"
    );
    let refused = (0..100).any(|_| {
        std::thread::sleep(Duration::from_millis(30));
        TcpStream::connect(("127.0.0.1", p.port)).is_err()
    });
    assert!(refused, "the listening socket closes when the drain starts");
    let st = p.wait(Duration::from_secs(10)).expect("exits");
    assert!(st.success(), "{st:?}");
}

#[test]
fn sigterm_lets_a_request_in_flight_finish() {
    let root = tmp("flight");
    let token = bootstrap(&root.0);
    let mut p = Proc::start(&root.0, &[]);
    let body = r#"{"name":"drained","auto_init":true}"#;
    let mut s = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let head = format!(
        "POST /api/v1/user/repos HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: token {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(&body.as_bytes()[..10]).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    p.sigterm();
    std::thread::sleep(Duration::from_millis(500));
    s.write_all(&body.as_bytes()[10..]).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 201"), "{resp}");
    let st = p.wait(Duration::from_secs(15)).expect("exits after it");
    assert!(st.success(), "{st:?}");
}

#[test]
fn a_stalled_request_does_not_hold_the_shutdown_past_its_deadline() {
    let root = tmp("stall");
    let token = bootstrap(&root.0);
    let mut p = Proc::start(&root.0, &["--shutdown-timeout", "2"]);
    let mut s = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
    s.write_all(
        format!(
            "POST /api/v1/user/repos HTTP/1.1\r\nHost: x\r\nAuthorization: token {token}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{{"
        )
        .as_bytes(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let t0 = Instant::now();
    p.sigterm();
    let st = p.wait(Duration::from_secs(20)).expect("exits");
    assert!(st.success(), "{st:?}");
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "exit took {:?}",
        t0.elapsed()
    );
    drop(s);
}

fn serve_with(tag: &str, listen: &str, extra: &[&str]) -> (Child, Tmp) {
    let root = tmp(tag);
    let child = Command::new(BIN)
        .args(["serve", "--data-dir"])
        .arg(root.0.join("data"))
        .args([
            "--listen",
            listen,
            "--public-url",
            "https://git.example.test",
        ])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    (child, root)
}

#[test]
fn a_public_plaintext_bind_is_refused_unless_the_operator_says_otherwise() {
    for listen in ["0.0.0.0:0", "[::]:0", "10.1.2.3:0", "[::ffff:127.0.0.1]:0"] {
        let (child, _root) = serve_with("refused", listen, &[]);
        let out = child.wait_with_output().unwrap();
        assert!(!out.status.success(), "{listen} must be refused");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("--behind-proxy") && err.contains("--allow-plaintext"),
            "{listen}: {err}"
        );
    }
}

#[test]
fn the_flags_that_allow_a_public_bind_do_start_the_server() {
    for flags in [&["--behind-proxy"][..], &["--allow-plaintext"][..]] {
        let (mut child, root) = serve_with("allowed", "0.0.0.0:0", flags);
        // Up when it logs that it listens; then stop it.
        let mut err = child.stderr.take().unwrap();
        let t0 = Instant::now();
        let mut seen = String::new();
        let mut buf = [0u8; 4096];
        while !seen.contains("listening on") && t0.elapsed() < Duration::from_secs(30) {
            let n = err.read(&mut buf).unwrap();
            assert!(n > 0, "the server exited early: {seen}");
            seen.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        assert!(seen.contains("listening on"), "{flags:?}: {seen}");
        // SAFETY: SIGTERM to the child this test spawned.
        unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        assert!(child.wait().unwrap().success());
        drop(root);
    }
}

#[test]
fn loopback_binds_need_no_flag() {
    for listen in ["127.0.0.1:0", "[::1]:0"] {
        let (mut child, _root) = serve_with("loopback", listen, &[]);
        std::thread::sleep(Duration::from_millis(1500));
        let still_running = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        assert!(still_running, "{listen} was refused");
    }
}

#[test]
fn logs_are_json_lines_and_carry_no_secret() {
    let root = tmp("logs");
    let token = bootstrap(&root.0);
    let mut p = Proc::start(&root.0, &[]);
    let password = "correct-horse-battery-staple-9f3";
    // A wrong password, a query that would carry a token if one were accepted there, a good call
    // with the token, a missing route, and a git clone with the token as the password.
    let basic = scl_forge::b64::encode(format!("siteadmin:{password}").as_bytes());
    let mut s = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
    s.write_all(
        format!(
            "GET /api/v1/user HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Basic {basic}\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink);
    p.get(
        &format!("/api/v1/version?access_token={token}&token={token}"),
        None,
    );
    p.get("/api/v1/user", Some(&token));
    p.get("/nope", None);
    let made = p
        .send(
            "POST",
            "/api/v1/user/repos",
            Some(&token),
            Some(&serde_json::json!({"name": "logged", "auto_init": true})),
        )
        .unwrap();
    assert_eq!(made.0, 201, "{}", made.1);
    let url = format!(
        "http://siteadmin:{token}@127.0.0.1:{}/siteadmin/logged.git",
        p.port
    );
    let dest = root.0.join("clone");
    let cloned = Command::new("git")
        .args(["clone", "-q", &url])
        .arg(&dest)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap();
    assert!(
        cloned.status.success(),
        "{}",
        String::from_utf8_lossy(&cloned.stderr)
    );
    p.sigterm();
    assert!(p.wait(Duration::from_secs(15)).is_some());
    let log = p.stderr();
    assert!(!log.is_empty());
    let mut requests = 0;
    for line in log.lines() {
        let v: Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("not a JSON line ({e}): {line}"));
        for k in ["time", "severity", "message"] {
            assert!(v[k].is_string(), "{k} missing: {line}");
        }
        if v["message"] == "request" {
            requests += 1;
            assert!(v["status"].is_u64() && v["ms"].is_u64(), "{line}");
            assert!(!v["path"].as_str().unwrap().contains('?'), "{line}");
        }
    }
    assert!(requests >= 5, "{requests} request lines:\n{log}");
    for secret in [token.as_str(), password, basic.as_str()] {
        assert!(!log.contains(secret), "a secret reached the log");
    }
    assert!(
        !log.contains("/api/healthz"),
        "successful health probes are not logged"
    );
    assert!(log.contains("listening on"), "{log}");
}
