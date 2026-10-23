//! Test harness: an in-process `sc-forge` on a loopback port, driven over raw
//! HTTP/1.1 on `std::net::TcpStream` (no HTTP client dependency, and the same
//! wire path a real client takes).
#![allow(dead_code)]

use scl_forge::limits::Proxies;
use scl_forge::server::{serve, Limits};
use scl_forge::{admin, db};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static N: AtomicUsize = AtomicUsize::new(0);

pub struct Srv {
    pub addr: SocketAddr,
    pub dir: PathBuf,
    pub base: String,
    /// All-scope token of the site admin `siteadmin`.
    pub admin: String,
    _data_lock: scl_forge::lifecycle::DirLock,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

pub struct Resp {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub raw: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.raw)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", String::from_utf8_lossy(&self.raw)))
    }
    pub fn msg(&self) -> String {
        self.json()["message"].as_str().unwrap_or("").to_string()
    }
}

pub fn b64(s: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in s.as_bytes().chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", b64(&format!("{user}:{pass}")))
}

pub fn token(t: &str) -> String {
    format!("token {t}")
}

impl Srv {
    pub fn start() -> Srv {
        Srv::start_with(Limits::default())
    }

    pub fn start_with(limits: Limits) -> Srv {
        Srv::start_cfg(limits, None)
    }

    /// Start with a custom password-failure policy.
    pub fn start_backoff(b: scl_forge::limits::Backoff) -> Srv {
        Srv::start_cfg(Limits::default(), Some(b))
    }

    fn start_cfg(limits: Limits, backoff: Option<scl_forge::limits::Backoff>) -> Srv {
        let dir = std::env::temp_dir().join(format!(
            "scl-forge-e2e-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        // Bootstrap exactly as Engine does: admin CLI on an empty data dir.
        admin::user_create(
            &dir,
            "siteadmin",
            &scl_crypto::generate_token(),
            "admin@example.invalid",
            true,
            false,
        )
        .unwrap();
        let admin_token =
            admin::generate_access_token(&dir, "siteadmin", "boot", &["all".to_string()]).unwrap();
        db::open_for_serve(&dir).unwrap();
        let std_l = TcpListener::bind("127.0.0.1:0").unwrap();
        std_l.set_nonblocking(true).unwrap();
        let addr = std_l.local_addr().unwrap();
        let base = format!("http://{addr}");
        let data_lock = scl_forge::lifecycle::DirLock::acquire(&dir).unwrap();
        let git = std::sync::Arc::new(
            scl_forge::gitproc::Git::new(&dir, scl_forge::gitproc::find_git().expect("git"), 8)
                .unwrap(),
        );
        let life = scl_forge::lifecycle::Lifecycle::new(&dir, git).unwrap();
        let mut app = scl_forge::routes::App::new(dir.clone(), &base, Proxies::default(), 4, life);
        if let Some(b) = backoff {
            app.backoff = b;
        }
        let app = std::sync::Arc::new(app);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let l = tokio::net::TcpListener::from_std(std_l).unwrap();
                serve(
                    l,
                    app,
                    limits,
                    async {
                        let _ = rx.await;
                    },
                    Duration::from_secs(5),
                )
                .await;
            });
        });
        Srv {
            _data_lock: data_lock,
            addr,
            dir,
            base,
            admin: admin_token,
            stop: Some(tx),
            thread: Some(thread),
        }
    }

    pub fn send(&self, method: &str, path: &str, auth: Option<&str>, body: Option<&Value>) -> Resp {
        let b = body.map(|v| v.to_string()).unwrap_or_default();
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.addr
        );
        if let Some(a) = auth {
            req += &format!("Authorization: {a}\r\n");
        }
        if body.is_some() {
            req += &format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            );
        }
        req += "\r\n";
        self.raw(req.as_bytes(), b.as_bytes())
    }

    pub fn raw(&self, head: &[u8], body: &[u8]) -> Resp {
        let mut s = TcpStream::connect(self.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.write_all(head).unwrap();
        s.write_all(body).unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        let split = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response head");
        let head = String::from_utf8_lossy(&buf[..split]).to_string();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers = lines
            .filter_map(|l| l.split_once(": "))
            .map(|(k, v)| (k.to_lowercase(), v.to_string()))
            .collect();
        Resp {
            status,
            headers,
            raw: buf[split + 4..].to_vec(),
        }
    }

    pub fn get(&self, path: &str, auth: &str) -> Resp {
        self.send("GET", path, Some(auth), None)
    }
    pub fn post(&self, path: &str, auth: &str, body: Value) -> Resp {
        self.send("POST", path, Some(auth), Some(&body))
    }

    /// Run git directly against repository `id`'s bare directory (the test's stand-in for a push,
    /// which F2b serves over HTTP).
    pub fn git(&self, id: i64, args: &[&str], stdin: Option<&[u8]>) -> String {
        let g = scl_forge::gitproc::Git::new(
            &self.dir,
            scl_forge::gitproc::find_git().expect("git"),
            4,
        )
        .unwrap();
        let dir = self.dir.join("repos").join(format!("{id}.git"));
        let id_ = scl_forge::gitproc::Identity::new("T", "t@example.invalid").unwrap();
        let out = g
            .run(&scl_forge::gitproc::Spec {
                repo: Some(&dir),
                args,
                stdin,
                identity: Some(&id_),
            })
            .unwrap();
        assert!(
            out.ok(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.text()
    }

    /// Make branch `name` in repository `id` point at a new empty commit on top of `parent` (or a root).
    pub fn commit_on(&self, id: i64, name: &str, parent: Option<&str>) -> String {
        let tree = self.git(id, &["mktree"], Some(b""));
        let mut args = vec!["commit-tree", tree.as_str()];
        if let Some(p) = parent {
            args.extend(["-p", p]);
        }
        let oid = self.git(id, &args, Some(b"msg\n"));
        self.git(
            id,
            &["update-ref", &format!("refs/heads/{name}"), &oid],
            None,
        );
        oid
    }

    /// Create a user through the admin API, returning (login, password).
    pub fn mk_user(&self, login: &str) -> String {
        let pw = format!("pw-{login}-0123456789");
        let r = self.post("/api/v1/admin/users", &token(&self.admin), serde_json::json!({
            "username": login, "email": format!("{login}@example.invalid"), "password": pw, "must_change_password": false
        }));
        assert_eq!(r.status, 201, "{}", r.msg());
        pw
    }

    /// Mint a token through the password route (what Portal does).
    pub fn mk_token(&self, login: &str, pw: &str, name: &str, scopes: &[&str]) -> String {
        let r = self.post(
            &format!("/api/v1/users/{login}/tokens"),
            &basic(login, pw),
            serde_json::json!({"name": name, "scopes": scopes}),
        );
        assert_eq!(r.status, 201, "{}", r.msg());
        r.json()["sha1"].as_str().unwrap().to_string()
    }
}

impl Drop for Srv {
    fn drop(&mut self) {
        if let Some(t) = self.stop.take() {
            let _ = t.send(());
        }
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
        std::fs::remove_dir_all(&self.dir).expect("test data dir must be removable");
        if !std::thread::panicking() {
            assert!(
                !self.dir.exists(),
                "test data dir must be gone after teardown"
            );
        }
    }
}
