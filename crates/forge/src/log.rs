//! Structured logs: one JSON object per line on stderr, shaped for Cloud Logging
//! (`time`, `severity`, `message`; further keys are fields).
//!
//! Nothing here sees a secret by construction: the access log records the method, the path
//! without its query, the status, the duration and the client address, never a header or a body,
//! and a message is built by the caller from facts the caller already holds. A value longer than
//! [`MAX_VALUE`] bytes is cut, so one hostile path or branch name cannot make a line unbounded.
//! Git hook messages bound for a pushing client (`hook.rs`) are not logs and do not come here.

use serde_json::{json, Map, Value};
use std::io::Write;

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

/// Write one log line to stderr.
pub fn emit(severity: &str, message: &str, fields: Option<Value>) {
    let mut line = render(crate::timefmt::now(), severity, message, fields);
    line.push('\n');
    // One write call keeps lines from interleaving; a closed stderr is not worth dying for.
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
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
}
