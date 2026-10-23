//! Serving a git request: admission, the `git http-backend` child, and the streams around it.
//!
//! One transport is a child process in its own group, owned by exactly one supervisor thread
//! (it signals the group while the leader is still an unreaped zombie, so the group id cannot have
//! been reused), plus three small threads: stdin writer, stdout reader and a stderr tail. The
//! request body reaches the child through a bounded channel fed by an async pump that enforces the
//! size cap, inflates gzip under a cap on *inflated* bytes and applies the idle deadline; the
//! child's output reaches the client through a bounded channel read by a streaming response body.
//! Nothing is buffered beyond those channels, so a clone or push costs a bounded amount of memory.
//!
//! What may be asked of git is decided in `transport.rs` before any of this runs.

use crate::http::Req;
use crate::registry::{Cancel, CancelOnDrop, Registration};
use crate::repos;
use crate::routes::App;
use crate::transport::{self, GitPath, Head, Held, Plan, Reserve, Service};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::Response;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

/// The response body type: a buffered answer or a stream from the child.
pub type RespBody = BoxBody<Bytes, std::io::Error>;

/// Transport limits (flags of `sc-forge serve`).
#[derive(Clone, Debug)]
pub struct Cfg {
    /// Transports in flight, all repositories.
    pub max_transports: usize,
    /// Transports in flight on one repository.
    pub per_repo: usize,
    /// How long a request waits for both slots before 503.
    pub admission_wait: Duration,
    /// Wall-clock limit of one transport.
    pub timeout: Duration,
    /// How long the server waits on a stalled client (no request bytes while the child wants some,
    /// or no room in the response while the child has some).
    pub idle: Duration,
    /// Largest push, bytes (also `receive.maxInputSize`).
    pub max_pack: u64,
    /// Largest upload-pack request, compressed and inflated.
    pub max_request: u64,
    /// Disk that must stay free beyond what pushes in flight have reserved.
    pub min_free: u64,
    /// Initial reservation of a push whose size is not announced.
    pub push_reserve: u64,
    /// `RLIMIT_CPU` of the child, seconds.
    pub cpu_secs: u64,
}

impl Default for Cfg {
    fn default() -> Cfg {
        Cfg {
            max_transports: 64,
            per_repo: 16,
            admission_wait: Duration::from_secs(30),
            timeout: Duration::from_secs(1800),
            idle: Duration::from_secs(120),
            max_pack: 2 << 30,
            max_request: 16 << 20,
            min_free: 1 << 30,
            push_reserve: 256 << 20,
            cpu_secs: 900,
        }
    }
}

/// Reservation grows in steps of this many bytes as a push is forwarded.
const GROW_STEP: u64 = 64 << 20;

/// Admission state: the two slot pools and the disk reservation.
pub struct Transports {
    pub cfg: Cfg,
    global: Arc<Semaphore>,
    per_repo: Mutex<HashMap<i64, Arc<Semaphore>>>,
    reserve: Arc<Reserve>,
}

/// Slots held for one transport; returned on drop.
pub struct Permits {
    _repo: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

impl Transports {
    pub fn new(cfg: Cfg) -> Transports {
        Transports {
            global: Arc::new(Semaphore::new(cfg.max_transports.max(1))),
            per_repo: Mutex::default(),
            reserve: Arc::new(Reserve::default()),
            cfg,
        }
    }

    fn repo_slots(&self, repo: i64) -> Arc<Semaphore> {
        let mut m = self.per_repo.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 256 {
            // Forget pools nobody uses (all permits home, no waiter holds the Arc).
            let full = self.cfg.per_repo.max(1);
            m.retain(|_, s| s.available_permits() < full || Arc::strong_count(s) > 1);
        }
        m.entry(repo)
            .or_insert_with(|| Arc::new(Semaphore::new(self.cfg.per_repo.max(1))))
            .clone()
    }

    /// Wait up to the admission deadline for a repository slot, then a global one (this order, so
    /// a flood on one repository queues behind its own limit instead of holding global slots
    /// while it waits). `None` means busy: the caller answers 503.
    pub async fn admit(&self, repo: i64) -> Option<Permits> {
        let repo_pool = self.repo_slots(repo);
        let global = self.global.clone();
        tokio::time::timeout(self.cfg.admission_wait, async move {
            let r = repo_pool.acquire_owned().await.ok()?;
            let g = global.acquire_owned().await.ok()?;
            Some(Permits {
                _repo: r,
                _global: g,
            })
        })
        .await
        .ok()
        .flatten()
    }

    /// Slots currently free (tests).
    pub fn free_slots(&self) -> usize {
        self.global.available_permits()
    }
}

// ---- the response body ----

/// A response body fed by the stdout reader thread. Dropping it (the client went away, or the
/// response finished) cancels the transport.
struct ChannelBody {
    rx: mpsc::Receiver<std::io::Result<Bytes>>,
    _guard: CancelOnDrop,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        self.rx.poll_recv(cx).map(|o| o.map(|r| r.map(Frame::data)))
    }
}

fn buffered(r: crate::http::Resp) -> Response<RespBody> {
    let mut b = Response::builder().status(r.status);
    for (k, v) in r.headers {
        b = b.header(k, v);
    }
    b.body(
        http_body_util::Full::new(Bytes::from(r.body))
            .map_err(|e| match e {})
            .boxed(),
    )
    .unwrap_or_else(|_| fallback(500))
}

fn fallback(status: u16) -> Response<RespBody> {
    let mut r = Response::new(
        http_body_util::Full::new(Bytes::from_static(b"internal server error\n"))
            .map_err(|e| match e {})
            .boxed(),
    );
    *r.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    r
}

fn text(status: u16, body: &str) -> crate::http::Resp {
    crate::http::Resp {
        status,
        headers: vec![("content-type", "text/plain;charset=utf-8".into())],
        body: body.as_bytes().to_vec(),
        delay: Duration::ZERO,
    }
}

// ---- the request pump ----

/// Inflates into a buffer and refuses to grow past `cap` bytes in total.
struct Sink {
    buf: Vec<u8>,
    total: u64,
    cap: u64,
    over: bool,
}

impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.total += b.len() as u64;
        if self.total > self.cap {
            self.over = true;
            return Err(std::io::Error::other("inflated request too large"));
        }
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Why the pump stopped the transport (the status the client gets if no response had started).
const ABORT_TIMEOUT: u16 = 408;
const ABORT_BAD: u16 = 400;
const ABORT_TOO_LARGE: u16 = 413;
const ABORT_NO_SPACE: u16 = 507;

struct Pump {
    body: Incoming,
    tx: mpsc::Sender<Bytes>,
    cancel: Cancel,
    abort: Arc<AtomicU16>,
    idle: Duration,
    cap: u64,
    gzip: bool,
    reservation: Option<Reservation>,
}

/// A push's disk reservation as the pump grows it.
struct Reservation {
    held: Arc<Mutex<Held>>,
    reserved: u64,
    data_dir: std::path::PathBuf,
    floor: u64,
}

impl Pump {
    fn stop(&self, status: u16) {
        self.abort.store(status, Ordering::SeqCst);
        self.cancel.cancel();
    }

    /// Hand `chunk` to the child; `false` when the pump must stop (the transport was cancelled).
    async fn send(&mut self, chunk: Bytes, forwarded: u64) -> bool {
        if let Some(r) = &mut self.reservation {
            while forwarded > r.reserved {
                let free = transport::free_bytes(&r.data_dir).unwrap_or(0);
                let ok = r
                    .held
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .grow(free, r.floor, GROW_STEP);
                if !ok {
                    eprintln!("sc-forge: push aborted: the disk reserve cannot cover it");
                    self.stop(ABORT_NO_SPACE);
                    return false;
                }
                r.reserved += GROW_STEP;
            }
        }
        tokio::select! {
            () = self.cancel.cancelled() => false,
            r = self.tx.send_timeout(chunk, self.idle) => match r {
                Ok(()) => true,
                Err(mpsc::error::SendTimeoutError::Timeout(_)) => { self.stop(ABORT_TIMEOUT); false }
                // The child stopped reading (it answered without the rest): not an error.
                Err(mpsc::error::SendTimeoutError::Closed(_)) => false,
            },
        }
    }

    async fn run(mut self) {
        let mut seen: u64 = 0;
        let mut forwarded: u64 = 0;
        let mut inflater = self.gzip.then(|| {
            flate2::write::GzDecoder::new(Sink {
                buf: Vec::new(),
                total: 0,
                cap: self.cap,
                over: false,
            })
        });
        loop {
            let frame = tokio::select! {
                () = self.cancel.cancelled() => return,
                f = tokio::time::timeout(self.idle, self.body.frame()) => f,
            };
            let frame = match frame {
                Err(_) => return self.stop(ABORT_TIMEOUT),
                Ok(None) => break,
                // The client's connection broke mid-request: end the transport.
                Ok(Some(Err(_))) => return self.cancel.cancel(),
                Ok(Some(Ok(f))) => f,
            };
            let Ok(data) = frame.into_data() else {
                continue;
            };
            seen += data.len() as u64;
            if seen > self.cap {
                return self.stop(ABORT_TOO_LARGE);
            }
            let pieces: Vec<Bytes> = match inflater.as_mut() {
                None => vec![data],
                Some(d) => {
                    let wrote = d.write_all(&data);
                    let sink = d.get_mut();
                    if wrote.is_err() {
                        let status = if sink.over {
                            ABORT_TOO_LARGE
                        } else {
                            ABORT_BAD
                        };
                        return self.stop(status);
                    }
                    pieces_of(std::mem::take(&mut sink.buf))
                }
            };
            for p in pieces {
                forwarded += p.len() as u64;
                if forwarded > self.cap && !self.gzip {
                    return self.stop(ABORT_TOO_LARGE);
                }
                if !self.send(p, forwarded).await {
                    return;
                }
            }
        }
        if let Some(d) = inflater {
            match d.finish() {
                Ok(mut sink) => {
                    for p in pieces_of(std::mem::take(&mut sink.buf)) {
                        forwarded += p.len() as u64;
                        if !self.send(p, forwarded).await {
                            return;
                        }
                    }
                }
                Err(_) => self.stop(ABORT_BAD),
            }
        }
        // Dropping the sender ends the child's stdin.
    }
}

fn pieces_of(buf: Vec<u8>) -> Vec<Bytes> {
    buf.chunks(64 * 1024).map(Bytes::copy_from_slice).collect()
}

// ---- the child ----

/// What a started transport hands back to the request task.
struct Started {
    head: oneshot::Receiver<Result<Head, &'static str>>,
    body: mpsc::Receiver<std::io::Result<Bytes>>,
    stdin: mpsc::Sender<Bytes>,
    cancel: Cancel,
}

/// Everything `launch` needs.
struct Launch {
    app: Arc<App>,
    plan: Plan,
    content_length: Option<u64>,
    content_type: Option<String>,
    git_protocol: Option<String>,
    remote: std::net::IpAddr,
    permits: Permits,
    held: Option<Arc<Mutex<Held>>>,
    rt: tokio::runtime::Handle,
}

enum LaunchError {
    /// The repository is gone or closing (delete): answer as for a missing repository.
    Gone,
    Io(std::io::Error),
}

impl From<std::io::Error> for LaunchError {
    fn from(e: std::io::Error) -> Self {
        LaunchError::Io(e)
    }
}

/// The CGI variables and git config of one transport, on top of the scrubbed base environment.
fn environment(l: &Launch) -> Vec<(String, String)> {
    let cfg = &l.app.transports.cfg;
    let git = &l.app.life.git;
    let extra = [
        ("transfer.hideRefs", "refs/forge/".to_string()),
        ("uploadpack.allowFilter", "true".into()),
        ("uploadpack.allowAnySHA1InWant", "true".into()),
        ("uploadpackfilter.allow", "false".into()),
        ("uploadpackfilter.blob:none.allow", "true".into()),
        ("receive.maxInputSize", cfg.max_pack.to_string()),
        ("receive.autogc", "false".into()),
        ("receive.advertisePushOptions", "true".into()),
    ];
    let mut env = git.env_with(None, &extra);
    let id = l.plan.access.repo.id;
    let mut var = |k: &str, v: String| env.push((k.to_string(), v));
    var(
        "GIT_PROJECT_ROOT",
        git.data_dir().join("repos").display().to_string(),
    );
    var("GIT_HTTP_EXPORT_ALL", "1".into());
    var(
        "PATH_INFO",
        format!("/{id}.git{}", l.plan.path.sub.path_info()),
    );
    var("REQUEST_METHOD", l.plan.path.sub.method().to_string());
    var(
        "QUERY_STRING",
        match l.plan.path.sub {
            transport::Sub::InfoRefs => l
                .plan
                .service
                .map(|s| format!("service={}", s.name()))
                .unwrap_or_default(),
            _ => String::new(),
        },
    );
    if let Some(ct) = &l.content_type {
        var("CONTENT_TYPE", ct.clone());
    }
    if let Some(n) = l.content_length {
        var("CONTENT_LENGTH", n.to_string());
    }
    if let Some(p) = &l.git_protocol {
        var("HTTP_GIT_PROTOCOL", p.clone());
    }
    if l.plan.may_write {
        var("REMOTE_USER", l.plan.user.login.clone());
    }
    var("REMOTE_ADDR", l.remote.to_string());
    var("GIT_HTTP_MAX_REQUEST_BUFFER", cfg.max_request.to_string());
    var("FORGE_DATA_DIR", git.data_dir().display().to_string());
    var("FORGE_REPO_ID", id.to_string());
    var("FORGE_USER_ID", l.plan.user.id.to_string());
    env
}

fn launch(l: Launch) -> Result<Started, LaunchError> {
    let repo_id = l.plan.access.repo.id;
    let cfg = l.app.transports.cfg.clone();
    let conn = crate::db::connect(&l.app.data_dir).map_err(std::io::Error::other)?;
    let reg = l
        .app
        .life
        .registry
        .register(
            repo_id,
            || matches!(repos::find_by_id(&conn, repo_id), Ok(Some(r)) if r.state == "live"),
        )
        .ok_or(LaunchError::Gone)?;
    let cancel = reg.cancel.clone();

    let git = &l.app.life.git;
    let (cpu, fsize) = (cfg.cpu_secs, cfg.max_pack.saturating_add(256 << 20));
    let mut cmd = Command::new(git.bin());
    cmd.arg("http-backend")
        .env_clear()
        .envs(environment(&l))
        .current_dir(git.data_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // SAFETY: the closure runs between fork and exec and only calls setrlimit (async-signal-safe).
    unsafe {
        cmd.pre_exec(move || {
            for (res, v) in [
                (libc::RLIMIT_CPU, cpu),
                (libc::RLIMIT_FSIZE, fsize),
                (libc::RLIMIT_CORE, 0),
            ] {
                let lim = libc::rlimit {
                    rlim_cur: v as libc::rlim_t,
                    rlim_max: v as libc::rlim_t,
                };
                // A refused limit (a lower hard limit already in force) is not fatal.
                let _ = libc::setrlimit(res, &lim);
            }
            Ok(())
        });
    }
    if cancel.is_set() {
        return Err(LaunchError::Gone);
    }
    let mut child = cmd.spawn()?;
    let pgid = child.id() as i32;
    let (stdin, stdout, stderr) = (
        child.stdin.take().expect("piped"),
        child.stdout.take().expect("piped"),
        child.stderr.take().expect("piped"),
    );

    let (stdin_tx, stdin_rx) = mpsc::channel::<Bytes>(4);
    let (body_tx, body_rx) = mpsc::channel::<std::io::Result<Bytes>>(4);
    let (head_tx, head_rx) = oneshot::channel();
    let (verdict_tx, verdict_rx) = std::sync::mpsc::channel::<bool>();

    let sup = Supervise {
        child,
        stderr,
        reg,
        _permits: l.permits,
        _held: l.held,
        verdict: verdict_tx,
        timeout: cfg.timeout,
        app: l.app.clone(),
        repo_id,
        receive: l.plan.service == Some(Service::Receive),
    };
    if let Err(e) = std::thread::Builder::new()
        .name("forge-supervise".into())
        .spawn(move || sup.run())
    {
        // The child is unreaped (a zombie holds its group id), so this signal is safe.
        // SAFETY: killpg only sends a signal to the group this call created.
        unsafe { libc::killpg(pgid, libc::SIGKILL) };
        return Err(e.into());
    }
    let stall = cfg.idle;
    let rt = l.rt.clone();
    let spawned = std::thread::Builder::new()
        .name("forge-stdin".into())
        .spawn(move || write_in(stdin, stdin_rx))
        .and_then(|_| {
            let c = cancel.clone();
            std::thread::Builder::new()
                .name("forge-stdout".into())
                .spawn(move || read_out(stdout, head_tx, body_tx, verdict_rx, stall, c, rt))
        });
    if let Err(e) = spawned {
        cancel.cancel(); // the supervisor kills the group
        return Err(e.into());
    }
    Ok(Started {
        head: head_rx,
        body: body_rx,
        stdin: stdin_tx,
        cancel,
    })
}

/// Copy the request to the child's stdin; dropping the handle at the end is its EOF.
fn write_in(mut stdin: ChildStdin, mut rx: mpsc::Receiver<Bytes>) {
    while let Some(b) = rx.blocking_recv() {
        if stdin.write_all(&b).is_err() {
            break; // the child exited or closed its input
        }
    }
}

/// Parse the CGI header block, report it, then stream the rest to the client. After the child
/// is reaped the supervisor's verdict decides whether the stream ends cleanly or with an error
/// (which makes the server drop the connection instead of terminating the chunked body).
fn read_out(
    mut out: ChildStdout,
    head_tx: oneshot::Sender<Result<Head, &'static str>>,
    body_tx: mpsc::Sender<std::io::Result<Bytes>>,
    verdict: std::sync::mpsc::Receiver<bool>,
    stall: Duration,
    cancel: Cancel,
    rt: tokio::runtime::Handle,
) {
    let forward = |item: std::io::Result<Bytes>| -> bool {
        rt.block_on(body_tx.send_timeout(item, stall)).is_ok()
    };
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 32 * 1024];
    let (head, rest) = loop {
        match out.read(&mut chunk) {
            Ok(0) | Err(_) => {
                let _ = head_tx.send(Err("git produced no response"));
                return;
            }
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                match transport::parse_head(&buf) {
                    Ok(Some((h, used))) => break (h, buf.split_off(used)),
                    Ok(None) => {}
                    Err(e) => {
                        let _ = head_tx.send(Err(e));
                        cancel.cancel();
                        return;
                    }
                }
            }
        }
    };
    if head_tx.send(Ok(head)).is_err() {
        return cancel.cancel(); // the request task is gone
    }
    if !rest.is_empty() && !forward(Ok(Bytes::from(rest))) {
        return cancel.cancel();
    }
    loop {
        match out.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if !forward(Ok(Bytes::copy_from_slice(&chunk[..n]))) {
                    return cancel.cancel(); // client gone or stalled
                }
            }
        }
    }
    if !verdict.recv().unwrap_or(false) {
        let _ = forward(Err(std::io::Error::other("git did not finish")));
    }
}

struct Supervise {
    child: Child,
    stderr: ChildStderr,
    reg: Registration,
    _permits: Permits,
    _held: Option<Arc<Mutex<Held>>>,
    verdict: std::sync::mpsc::Sender<bool>,
    timeout: Duration,
    app: Arc<App>,
    repo_id: i64,
    receive: bool,
}

impl Supervise {
    fn run(self) {
        let Supervise {
            mut child,
            stderr,
            reg,
            verdict,
            timeout,
            app,
            repo_id,
            receive,
            ..
        } = self;
        let pgid = child.id() as i32;
        let cancel = reg.cancel.clone();
        let tail = std::thread::Builder::new()
            .name("forge-stderr".into())
            .spawn(move || stderr_tail(stderr))
            .ok();
        let end = Instant::now() + timeout;
        let mut nap = Duration::from_millis(2);
        // Detect exit without reaping: while the leader is a zombie its pid, and so the group id,
        // cannot be reused. Signal the group first, reap after.
        let reason = loop {
            match crate::gitproc::exited_unreaped(pgid) {
                Ok(true) => break "exited",
                Ok(false) => {}
                Err(_) => break "lost",
            }
            if cancel.is_set() {
                break "cancelled";
            }
            if Instant::now() >= end {
                break "timed out";
            }
            std::thread::sleep(nap);
            nap = (nap * 2).min(Duration::from_millis(50));
        };
        // SAFETY: killpg only sends a signal; the leader is unreaped, so the group id is ours.
        unsafe { libc::killpg(pgid, libc::SIGKILL) };
        let status = child.wait();
        let ok = reason == "exited" && status.as_ref().is_ok_and(|s| s.success());
        let _ = verdict.send(ok);
        let err = tail.and_then(|t| t.join().ok()).unwrap_or_default();
        if !ok {
            eprintln!(
                "sc-forge: git transport on repository {repo_id} ended ({reason}, {}): {}",
                status.map_or_else(|e| e.to_string(), |s| s.to_string()),
                String::from_utf8_lossy(&err).trim()
            );
        } else if receive {
            if let Ok(conn) = crate::db::connect(&app.data_dir) {
                let _ = repos::touch(&conn, repo_id, crate::timefmt::now());
            }
        }
        // Wake the request pump, which may still be waiting on the client.
        cancel.cancel();
    }
}

/// The last few KiB of the child's stderr (drained to EOF so it never blocks on a full pipe).
fn stderr_tail(mut e: ChildStderr) -> Vec<u8> {
    const KEEP: usize = 4096;
    let mut tail: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = e.read(&mut buf) {
        if n == 0 {
            break;
        }
        tail.extend_from_slice(&buf[..n]);
        if tail.len() > KEEP {
            tail.drain(..tail.len() - KEEP);
        }
    }
    tail
}

// ---- the request task ----

/// Serve one git request: the caller has matched the path to `path`.
pub async fn handle(app: Arc<App>, req: Req, body: Incoming, path: GitPath) -> Response<RespBody> {
    let req = Arc::new(req);
    let plan = {
        let (app, req) = (app.clone(), req.clone());
        match tokio::task::spawn_blocking(move || transport::authorize(&app, &req, path)).await {
            Ok(Ok(p)) => p,
            Ok(Err(r)) => return buffered(r),
            Err(_) => return buffered(text(500, "internal server error\n")),
        }
    };
    let t = &app.transports;
    let service = plan.service;
    let is_receive = service == Some(Service::Receive);
    let has_body = plan.path.sub.method() == "POST";
    let content_length = match req
        .header("content-length")
        .map(|v| v.trim().parse::<u64>())
    {
        None => None,
        Some(Ok(n)) => Some(n),
        Some(Err(_)) => return buffered(text(400, "Bad Request\n")),
    };
    let gzip = match req
        .header("content-encoding")
        .map(|v| v.trim().to_ascii_lowercase())
    {
        None => false,
        Some(e) if e == "identity" => false,
        Some(e) if (e == "gzip" || e == "x-gzip") && service == Some(Service::Upload) => true,
        Some(_) => return buffered(text(415, "Unsupported Media Type\n")),
    };
    let cap = if is_receive {
        t.cfg.max_pack
    } else {
        t.cfg.max_request
    };
    if has_body && content_length.is_some_and(|n| n > cap) {
        return buffered(text(413, "Request Entity Too Large\n"));
    }
    let repo_id = plan.access.repo.id;
    let Some(permits) = t.admit(repo_id).await else {
        return buffered(text(503, "Service Unavailable\n").with("retry-after", "5".into()));
    };
    let mut reservation = None;
    let mut held = None;
    if is_receive {
        let need = content_length
            .map_or(t.cfg.push_reserve, |n| n.min(cap))
            .max(1);
        let free = transport::free_bytes(&app.data_dir).unwrap_or(0);
        match t.reserve.reserve(free, t.cfg.min_free, need) {
            Some(h) => {
                let h = Arc::new(Mutex::new(h));
                held = Some(h.clone());
                reservation = Some(Reservation {
                    held: h,
                    reserved: need,
                    data_dir: app.data_dir.clone(),
                    floor: t.cfg.min_free,
                });
            }
            None => return buffered(text(507, "Insufficient Storage\n")),
        }
    }
    let launch_args = Launch {
        app: app.clone(),
        content_length: (!gzip && has_body).then_some(content_length).flatten(),
        content_type: has_body
            .then(|| transport::content_type(req.header("content-type")))
            .flatten(),
        git_protocol: transport::protocol_header(req.header("git-protocol")),
        remote: req.source,
        plan,
        permits,
        held,
        rt: tokio::runtime::Handle::current(),
    };
    let started = match tokio::task::spawn_blocking(move || launch(launch_args)).await {
        Ok(Ok(s)) => s,
        Ok(Err(LaunchError::Gone)) => return buffered(transport::repo_not_found()),
        Ok(Err(LaunchError::Io(e))) => {
            eprintln!("sc-forge: could not start git: {e}");
            return buffered(text(500, "internal server error\n"));
        }
        Err(_) => return buffered(text(500, "internal server error\n")),
    };
    let Started {
        head,
        body: out,
        stdin,
        cancel,
    } = started;
    // From here, dropping this guard (the client went away, or we return an error) ends the child.
    let guard = cancel.on_drop();
    let abort = Arc::new(AtomicU16::new(0));
    if has_body {
        tokio::spawn(
            Pump {
                body,
                tx: stdin,
                cancel: cancel.clone(),
                abort: abort.clone(),
                idle: t.cfg.idle,
                cap,
                gzip,
                reservation,
            }
            .run(),
        );
    }
    let head = match head.await {
        Ok(Ok(h)) => h,
        other => {
            let why = abort.load(Ordering::SeqCst);
            let status = if why != 0 { why } else { 502 };
            if let Ok(Err(e)) = other {
                eprintln!("sc-forge: git transport failed before answering: {e}");
            }
            return buffered(text(status, "git transport failed\n"));
        }
    };
    let mut b = Response::builder().status(head.status);
    for (k, v) in head.headers {
        b = b.header(k, v);
    }
    b.body(
        ChannelBody {
            rx: out,
            _guard: guard,
        }
        .boxed(),
    )
    .unwrap_or_else(|_| fallback(502))
}

/// A plain (non-streamed) answer as a response, for the server's own use.
pub fn answer(r: crate::http::Resp) -> Response<RespBody> {
    buffered(r)
}
