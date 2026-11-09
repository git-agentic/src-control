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
    let mut p = Proc::start(&root.0, &["--shutdown-timeout", "3"]);
    // A keep-alive client that went idle after its request.
    let mut idle = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
    idle.write_all(b"GET /api/healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 1024];
    assert!(idle.read(&mut buf).unwrap() > 0, "the first response");
    // A stalled request keeps the drain open, so what follows is observed while the server is still up.
    let mut stalled = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
    stalled
        .write_all(
            b"POST /api/v1/user/repos HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{",
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    p.sigterm();
    // Closed by the server at once, not after the drain deadline.
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
    assert!(
        p.child.try_wait().unwrap().is_none(),
        "the server is still draining the stalled request"
    );
    let st = p.wait(Duration::from_secs(20)).expect("exits");
    assert!(st.success(), "{st:?}");
    drop(stalled);
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

/// A repository holding `len` bytes of incompressible content, pushed with a scrubbed git; returns
/// the tip commit.
fn big_repo(p: &Proc, root: &Path, token: &str, name: &str, len: usize) -> String {
    let created = p
        .send(
            "POST",
            "/api/v1/user/repos",
            Some(token),
            Some(&serde_json::json!({"name": name, "default_branch": "main"})),
        )
        .unwrap();
    assert_eq!(created.0, 201, "{}", created.1);
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
            .env("HOME", root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "T")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "T")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .current_dir(&work)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    git(&["init", "-q", "-b", "main"]);
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    let bytes: Vec<u8> = (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    std::fs::write(work.join("big.bin"), bytes).unwrap();
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "big"]);
    let url = format!("http://127.0.0.1:{}/siteadmin/{name}.git", p.port);
    let auth = format!("http.extraHeader=Authorization: token {token}");
    git(&["-c", &auth, "push", "-q", &url, "main"]);
    git(&["rev-parse", "HEAD"])
}

/// Ask for `want`'s whole pack and read only the response head: the upload-pack is then
/// mid-transfer, blocked on this socket, until the rest is read.
fn held_fetch(p: &Proc, token: &str, name: &str, want: &str) -> TcpStream {
    let body = format!("0032want {want}\n00000009done\n");
    let mut s = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(
        s,
        "POST /siteadmin/{name}.git/git-upload-pack HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: token {token}\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut head = [0u8; 12];
    s.read_exact(&mut head).unwrap();
    assert_eq!(&head, b"HTTP/1.1 200", "the transfer started");
    s
}

/// The process groups of the server's children (each git transport leads its own group).
fn child_groups(server: u32) -> Vec<String> {
    let out = Command::new("pgrep")
        .args(["-P", &server.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

fn group_alive(pgid: &str) -> bool {
    Command::new("pgrep")
        .args(["-g", pgid])
        .output()
        .unwrap()
        .status
        .success()
}

/// `(ended with the terminating chunk, bytes)` for the rest of a held response.
fn rest_of(mut s: TcpStream) -> (bool, usize) {
    let mut buf = Vec::new();
    match s.read_to_end(&mut buf) {
        Ok(_) => {}
        // A cut connection may end in a reset; a timeout means the server left it hanging.
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("the response neither ended nor broke: {e}"),
    }
    (buf.ends_with(b"\r\n0\r\n\r\n"), buf.len())
}

#[test]
fn sigterm_lets_a_clone_in_flight_finish_within_the_drain() {
    let root = tmp("clone-drain");
    let token = bootstrap(&root.0);
    let mut p = Proc::start(&root.0, &["--shutdown-timeout", "30"]);
    let want = big_repo(&p, &root.0, &token, "drained", 16 << 20);
    let held = held_fetch(&p, &token, "drained", &want);
    p.sigterm();
    std::thread::sleep(Duration::from_millis(300)); // the drain has begun
    assert!(
        p.child.try_wait().unwrap().is_none(),
        "the server waits for the transfer"
    );
    let (clean, got) = rest_of(held);
    assert!(clean && got > 16 << 20, "{got} bytes, clean: {clean}");
    let st = p.wait(Duration::from_secs(20)).expect("exits after it");
    assert!(st.success(), "{st:?}");
}

#[test]
fn sigterm_cancels_a_clone_still_running_at_the_drain_deadline() {
    let root = tmp("clone-cancel");
    let token = bootstrap(&root.0);
    let mut p = Proc::start(&root.0, &["--shutdown-timeout", "2"]);
    let want = big_repo(&p, &root.0, &token, "cancelled", 16 << 20);
    let held = held_fetch(&p, &token, "cancelled", &want);
    let groups = child_groups(p.child.id());
    assert!(!groups.is_empty(), "the transfer's git is running");
    let t0 = Instant::now();
    p.sigterm();
    let st = p.wait(Duration::from_secs(15)).expect("exits");
    assert!(st.success(), "{st:?}");
    // It waited out the two-second drain for the transfer, then cut it.
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(1900) && took < Duration::from_secs(10),
        "{took:?}"
    );
    // Read only now: the transfer was cut, so the response has no terminating chunk (a client
    // sees an error, not a clean but truncated pack), and no git outlives the server.
    let (clean, got) = rest_of(held);
    assert!(!clean, "{got} bytes ended cleanly");
    for g in &groups {
        assert!(!group_alive(g), "git process group {g} survived the server");
    }
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

/// Start `serve` with its stderr in a file; returns once it logs "listening on" (or fails the test).
fn serve_to_file(tag: &str, listen: &str, extra: &[&str]) -> (Child, PathBuf, Tmp) {
    let root = tmp(tag);
    let log = root.0.join("stderr.log");
    let mut child = Command::new(BIN)
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
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let t0 = Instant::now();
    loop {
        if std::fs::read_to_string(&log).is_ok_and(|t| t.contains("listening on")) {
            return (child, log, root);
        }
        if let Some(st) = child.try_wait().unwrap() {
            panic!(
                "{listen} {extra:?} exited early ({st:?}): {}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
        }
        assert!(
            t0.elapsed() < Duration::from_secs(30),
            "{listen} never listened"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn stop(mut child: Child) -> ExitStatus {
    // SAFETY: SIGTERM to the child this test spawned.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let t0 = Instant::now();
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return st;
        }
        if t0.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("no exit after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_flags_that_allow_a_public_bind_do_start_the_server() {
    for (i, flags) in [&["--behind-proxy"][..], &["--allow-plaintext"][..]]
        .into_iter()
        .enumerate()
    {
        let (child, _log, _root) = serve_to_file(&format!("allowed{i}"), "0.0.0.0:0", flags);
        let st = stop(child);
        assert!(st.success(), "{flags:?}: {st:?}");
    }
}

#[test]
fn loopback_binds_need_no_flag() {
    let mut addrs = vec!["127.0.0.1:0"];
    // A host without IPv6 cannot bind [::1] whatever the gate says.
    if std::net::TcpListener::bind("[::1]:0").is_ok() {
        addrs.push("[::1]:0");
    }
    for (i, listen) in addrs.into_iter().enumerate() {
        let (child, _log, _root) = serve_to_file(&format!("loop{i}"), listen, &[]);
        assert!(stop(child).success(), "{listen}");
    }
}

#[test]
fn a_log_consumer_that_stops_reading_does_not_stall_the_server() {
    let root = tmp("stuck");
    let data = root.0.join("data");
    let port = free_port();
    // stderr is a pipe nobody reads: once it is full, log writes block.
    let mut child = Command::new(BIN)
        .args(["serve", "--data-dir"])
        .arg(&data)
        .args([
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--public-url",
            &format!("http://127.0.0.1:{port}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let get = |path: &str| -> Option<u16> {
        let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .ok()?;
        let mut b = String::new();
        s.read_to_string(&mut b).ok()?;
        b.split(' ').nth(1)?.parse().ok()
    };
    let t0 = Instant::now();
    while get("/api/healthz") != Some(200) {
        assert!(t0.elapsed() < Duration::from_secs(30), "no start");
        std::thread::sleep(Duration::from_millis(50));
    }
    // Far more request lines than a pipe (64 KiB) plus the log queue (4096 lines) can hold.
    std::thread::scope(|sc| {
        for _ in 0..8 {
            sc.spawn(|| {
                for _ in 0..800 {
                    let _ = get("/nope");
                }
            });
        }
    });
    assert_eq!(
        get("/api/healthz"),
        Some(200),
        "the server must still answer"
    );
    // SAFETY: SIGTERM to the child this test spawned.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let t0 = Instant::now();
    let st = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if t0.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            panic!("the drain hung behind a blocked log pipe");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(st.success(), "{st:?}");
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
