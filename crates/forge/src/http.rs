//! Request/response types and Gitea's JSON error shapes.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// A fully read request, handed to the synchronous router.
pub struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    /// Header names lower-cased.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    /// The client address after trusted-proxy resolution (rate-limit key).
    pub source: IpAddr,
}

impl Req {
    /// The request header `name` (lower case), if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// First value of query parameter `key`, percent-decoding not applied
    /// (F1 parameters are plain integers).
    pub fn param(&self, key: &str) -> Option<&str> {
        self.query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    }
}

/// A response the server writes out.
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
    /// Held back by the server before writing (failed-login backoff), on the
    /// async runtime so it occupies no blocking thread.
    pub delay: Duration,
    /// Dropped once the body has been written (or the connection died): a resource budget that
    /// must cover the response's bytes in flight, not just the handler.
    pub hold: Option<Box<dyn std::any::Any + Send + Sync>>,
}

const JSON_CT: &str = "application/json;charset=utf-8";

impl Resp {
    /// A JSON response with Gitea's content type.
    pub fn json(status: u16, v: &Value) -> Resp {
        Resp {
            status,
            headers: vec![("content-type", JSON_CT.into())],
            body: serde_json::to_vec(v).expect("serializing a Value cannot fail"),
            delay: Duration::ZERO,
            hold: None,
        }
    }

    /// An empty 204.
    pub fn no_content() -> Resp {
        Resp {
            status: 204,
            headers: vec![],
            body: vec![],
            delay: Duration::ZERO,
            hold: None,
        }
    }

    /// Hold the response back by `d` before it is written.
    pub fn delayed(mut self, d: Duration) -> Resp {
        self.delay = d;
        self
    }

    /// Add a response header.
    pub fn with(mut self, name: &'static str, value: String) -> Resp {
        self.headers.push((name, value));
        self
    }
}

/// Where Gitea's error bodies point (`url`); built from `--public-url`.
fn swagger(base: &str) -> String {
    format!("{base}/api/swagger")
}

/// `{"message", "url"}` with the recorded status and text.
pub fn error(base: &str, status: u16, message: &str) -> Resp {
    Resp::json(status, &json!({"message": message, "url": swagger(base)}))
}

/// Gitea's 404 shape: `errors` is null or a list of detail strings.
pub fn not_found(base: &str, message: &str, errors: Option<&str>) -> Resp {
    Resp::json(
        404,
        &json!({"errors": errors.map(|e| vec![e]), "message": message, "url": swagger(base)}),
    )
}

/// The anonymous 403 recorded on every API route: no `url` key.
pub fn signed_in_only() -> Resp {
    Resp::json(
        403,
        &json!({"message": "Only signed in user is allowed to call APIs."}),
    )
}
