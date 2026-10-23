//! The HTTP listener: hyper (http1) over tokio. Bounded body, header-read
//! timeout and connection cap here; routing, SQLite and Argon2 run on blocking
//! threads in `routes::dispatch`.

use crate::http::{Req, Resp};
use crate::limits::Proxies;
use crate::routes::{dispatch, App};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// `Server:` header value: the server's own identity (`/version` answers
/// Gitea's number because clients sniff it).
const SERVER: &str = concat!("sc-forge/", env!("CARGO_PKG_VERSION"));

/// Listener limits.
#[derive(Clone)]
pub struct Limits {
    pub max_body: usize,
    pub max_connections: usize,
    pub header_timeout: Duration,
    /// Time allowed to receive a request body once its headers arrived.
    pub body_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_body: 1 << 20,
            max_connections: 512,
            header_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(30),
        }
    }
}

/// Refuse to bind a non-loopback address in plaintext unless the operator said
/// so: tokens and passwords cross this socket.
pub fn bind_gate(
    addr: &SocketAddr,
    behind_proxy: bool,
    allow_plaintext: bool,
) -> Result<(), String> {
    if addr.ip().is_loopback() || behind_proxy || allow_plaintext {
        return Ok(());
    }
    Err(format!(
        "refusing to listen on {addr}: it is not loopback and this server speaks plaintext HTTP; \
         put it behind a TLS proxy and pass --behind-proxy, or pass --allow-plaintext"
    ))
}

async fn handle(
    app: Arc<App>,
    limits: Limits,
    peer: IpAddr,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let (parts, body) = req.into_parts();
    let headers = parts
        .headers
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect::<std::collections::HashMap<_, _>>();
    let body = match tokio::time::timeout(
        limits.body_timeout,
        Limited::new(body, limits.max_body).collect(),
    )
    .await
    {
        Ok(Ok(b)) => b.to_bytes().to_vec(),
        Ok(Err(_)) => {
            return Ok(to_response(crate::http::error(
                &app.base,
                413,
                "request body too large",
            )))
        }
        Err(_) => {
            return Ok(to_response(crate::http::error(
                &app.base,
                408,
                "request body timed out",
            )))
        }
    };
    let source = app.proxies.resolve(
        peer,
        headers
            .get(app.proxies.header.as_deref().unwrap_or(""))
            .map(String::as_str),
    );
    let r = Req {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().unwrap_or("").to_string(),
        headers,
        body,
        source,
    };
    let resp = tokio::task::spawn_blocking(move || dispatch(&app, &r))
        .await
        .unwrap_or_else(|_| {
            Resp::json(
                500,
                &serde_json::json!({"message": "internal server error"}),
            )
        });
    if !resp.delay.is_zero() {
        tokio::time::sleep(resp.delay).await;
    }
    Ok(to_response(resp))
}

fn to_response(r: Resp) -> Response<Full<Bytes>> {
    let mut b = Response::builder()
        .status(r.status)
        .header("server", SERVER);
    for (k, v) in r.headers {
        b = b.header(k, v);
    }
    b.body(Full::new(Bytes::from(r.body)))
        .expect("static header names are valid")
}

/// Serve until `shutdown` resolves, then wait up to `drain` for in-flight
/// connections. A connection beyond `max_connections` is closed at accept.
pub async fn serve(
    listener: TcpListener,
    app: Arc<App>,
    limits: Limits,
    shutdown: impl std::future::Future<Output = ()>,
    drain: Duration,
) {
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let mut conns = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                let (app, limits) = (app.clone(), limits.clone());
                let header_timeout = limits.header_timeout;
                conns.spawn(async move {
                    let svc = service_fn(move |req| handle(app.clone(), limits.clone(), peer.ip(), req));
                    let mut http = hyper::server::conn::http1::Builder::new();
                    http.timer(TokioTimer::new()).header_read_timeout(header_timeout);
                    let _ = http.serve_connection(TokioIo::new(stream), svc).await;
                    drop(permit);
                });
            }
        }
    }
    let _ = tokio::time::timeout(drain, async { while conns.join_next().await.is_some() {} }).await;
}

/// Build the shared state from CLI inputs.
pub fn make_app(
    data_dir: std::path::PathBuf,
    public_url: &str,
    proxies: Proxies,
    argon_slots: usize,
) -> Arc<App> {
    Arc::new(App::new(data_dir, public_url, proxies, argon_slots))
}
