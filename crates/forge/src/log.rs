//! Structured logs: one JSON object per line on stderr, shaped for Cloud Logging
//! (`time`, `severity`, `message`; further keys are fields).
//!
//! Nothing here sees a secret by construction: the access log records the method, the path
//! without its query, the status, the duration and the client address, never a header or a body,
//! and a message is built by the caller from facts the caller already holds. A value longer than
//! [`MAX_VALUE`] bytes is cut, so one hostile path or branch name cannot make a line unbounded.
//! Writes go through a bounded queue to one writer thread, so a stderr that nobody reads cannot freeze
//! request handling (lines are dropped and counted instead). Git hook messages bound for a pushing client (`hook.rs`) are not logs and do not come here.

use serde_json::{json, Map, Value};
use std::io::Write;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

/// The longest string kept in a log line, in bytes.
pub const MAX_VALUE: usize = 512;

fn clip(s: &str) -> String {
    if s.len() <= MAX_VALUE {
        return s.to_string();
    }
    let mut end = MAX_VALUE;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Render one line (without the newline). Fields may not overwrite `time`, `severity` or `message`.
pub fn render(time: i64, severity: &str, message: &str, fields: Option<Value>) -> String {
    let mut m = Map::new();
    if let Some(Value::Object(f)) = fields {
        for (k, v) in f {
            let v = match v {
                Value::String(s) => Value::String(clip(&s)),
                other => other,
            };
            m.insert(k, v);
        }
    }
    m.insert("time".into(), json!(crate::timefmt::rfc3339(time)));
    m.insert("severity".into(), json!(severity));
    m.insert("message".into(), json!(clip(message)));
    Value::Object(m).to_string()
}

/// Lines waiting for the writer thread before new ones are dropped.
const QUEUE: usize = 4096;

struct Sink {
    tx: std::sync::mpsc::SyncSender<String>,
    pending: AtomicUsize,
    dropped: AtomicU64,
}

fn sink() -> &'static Sink {
    static SINK: OnceLock<Sink> = OnceLock::new();
    SINK.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(QUEUE);
        std::thread::Builder::new()
            .name("log-writer".into())
            .spawn(move || {
                for line in rx {
                    // A stderr nobody reads blocks here, not in a request handler.
                    let _ = std::io::stderr().lock().write_all(line.as_bytes());
                    sink().pending.fetch_sub(1, Ordering::SeqCst);
                }
            })
            .expect("start the log writer");
        Sink {
            tx,
            pending: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
        }
    })
}

/// Queue one log line for stderr. Never blocks: a stalled log consumer must not stall requests, the
/// drain or signal handling, so when the queue is full the line is dropped and counted (the next
/// line that fits is preceded by a note of how many were lost).
pub fn emit(severity: &str, message: &str, fields: Option<Value>) {
    let sink = sink();
    let now = crate::timefmt::now();
    let lost = sink.dropped.swap(0, Ordering::SeqCst);
    if lost > 0 {
        let note = render(
            now,
            "WARNING",
            "log lines were dropped: stderr is not being read",
            Some(json!({ "dropped": lost })),
        );
        if !enqueue(sink, note) {
            sink.dropped.fetch_add(lost, Ordering::SeqCst);
        }
    }
    if !enqueue(sink, render(now, severity, message, fields)) {
        sink.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn enqueue(sink: &Sink, mut line: String) -> bool {
    line.push('\n');
    sink.pending.fetch_add(1, Ordering::SeqCst);
    if sink.tx.try_send(line).is_ok() {
        true
    } else {
        sink.pending.fetch_sub(1, Ordering::SeqCst);
        false
    }
}

/// Wait up to two seconds for queued lines to reach stderr (before the process exits).
pub fn flush() {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while sink().pending.load(Ordering::SeqCst) > 0 && std::time::Instant::now() < end {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// `INFO` line from a message (for the binary, which cannot use the crate-private macros).
pub fn info_line(message: &str) {
    emit("INFO", message, None);
}

/// `WARNING` line from a message.
pub fn warning_line(message: &str) {
    emit("WARNING", message, None);
}

macro_rules! info {
    ($($arg:tt)*) => { $crate::log::emit("INFO", &format!($($arg)*), None) };
}
macro_rules! warning {
    ($($arg:tt)*) => { $crate::log::emit("WARNING", &format!($($arg)*), None) };
}
macro_rules! error {
    ($($arg:tt)*) => { $crate::log::emit("ERROR", &format!($($arg)*), None) };
}
pub(crate) use {error, info, warning};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_one_json_object_with_the_reserved_keys_last() {
        let l = render(
            0,
            "INFO",
            "hello \"world\"\nnext",
            Some(json!({"message": "spoof", "status": 200})),
        );
        assert!(!l.contains('\n'), "the newline is escaped");
        let v: Value = serde_json::from_str(&l).unwrap();
        assert_eq!(v["message"], "hello \"world\"\nnext");
        assert_eq!(v["severity"], "INFO");
        assert_eq!(v["time"], "1970-01-01T00:00:00Z");
        assert_eq!(v["status"], 200);
    }

    #[test]
    fn long_values_are_cut_on_a_character_boundary() {
        let long = "é".repeat(MAX_VALUE);
        let l = render(0, "INFO", &long, Some(json!({"path": long})));
        let v: Value = serde_json::from_str(&l).unwrap();
        assert!(v["path"].as_str().unwrap().len() <= MAX_VALUE + 3);
        assert!(v["message"].as_str().unwrap().ends_with('…'));
    }

    #[test]
    fn a_full_queue_drops_instead_of_blocking() {
        // A sink whose writer never runs: after QUEUE lines the next ones are refused, not waited on.
        let (tx, _rx) = std::sync::mpsc::sync_channel::<String>(QUEUE);
        let sink = Sink {
            tx,
            pending: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
        };
        let started = std::time::Instant::now();
        let kept = (0..QUEUE + 10)
            .filter(|i| enqueue(&sink, format!("line {i}")))
            .count();
        assert_eq!(kept, QUEUE);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(sink.pending.load(Ordering::SeqCst), QUEUE);
    }
}
