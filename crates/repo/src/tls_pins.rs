//! Client-side TOFU pin store for sc+https:// (P32): a user-level
//! known_hosts file, one line per `host:port`, format
//! `host:port sha256:<hex>` — plus the env knobs that shape a connection's
//! pin policy. The repo layer owns pin PERSISTENCE and POLICY; the actual
//! in-handshake check lives in scl-tlsio's verifier.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The pin policy for one client connection, resolved from env by
/// [`TlsClientPolicy::from_env`] or built directly by tests (env mutation is
/// process-global and racy under parallel tests — the
/// `connect_with_token`/`connect_with_pins` split exists for this).
#[derive(Debug, Clone)]
pub struct TlsClientPolicy {
    pub known_hosts: PathBuf,
    /// `SC_HTTPS_FINGERPRINT`: verified for this process only, never
    /// persisted (CI-friendly).
    pub pre_pin: Option<[u8; 32]>,
    /// `SC_HTTPS_STRICT`: refuse unknown hosts instead of accept-new.
    /// `=1` enables it; any non-empty value other than `0` is also treated
    /// as enabled (fails closed on typos like `=true`/`=yes` rather than
    /// silently falling back to accept-new — see [`strict_from`]).
    pub strict: bool,
}

impl TlsClientPolicy {
    pub fn from_env() -> Result<TlsClientPolicy> {
        let known_hosts = known_hosts_path()?;
        let pre_pin = match std::env::var("SC_HTTPS_FINGERPRINT") {
            Ok(s) if !s.is_empty() => Some(parse_fingerprint(&s)?),
            _ => None,
        };
        let strict = strict_from(std::env::var("SC_HTTPS_STRICT").ok().as_deref());
        Ok(TlsClientPolicy {
            known_hosts,
            pre_pin,
            strict,
        })
    }
}

/// Pure decision for `SC_HTTPS_STRICT`: unset, empty, or `"0"` means not
/// strict; any other value (including typos like `"true"`/`"yes"`) means
/// strict. Fails closed rather than silently disabling strict mode on an
/// unrecognized value. Factored out of [`TlsClientPolicy::from_env`] so it
/// can be unit-tested without mutating process env (racy under parallel
/// tests).
fn strict_from(value: Option<&str>) -> bool {
    match value {
        None => false,
        Some(v) if v.is_empty() || v == "0" => false,
        Some(_) => true,
    }
}

/// The pin file in effect: `SC_HTTPS_KNOWN_HOSTS` if set and non-empty, else
/// [`default_known_hosts_path`].
pub fn known_hosts_path() -> Result<PathBuf> {
    match std::env::var_os("SC_HTTPS_KNOWN_HOSTS") {
        Some(p) if !p.is_empty() => Ok(PathBuf::from(p)),
        _ => default_known_hosts_path(),
    }
}

/// `$XDG_CONFIG_HOME/sc/known_hosts`, falling back to
/// `$HOME/.config/sc/known_hosts`.
pub fn default_known_hosts_path() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("sc").join("known_hosts"));
    }
    match std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        Some(home) => Ok(PathBuf::from(home)
            .join(".config")
            .join("sc")
            .join("known_hosts")),
        None => Err(Error::InvalidArgument(
            "cannot resolve the sc+https pin file: set HOME, XDG_CONFIG_HOME, \
             or SC_HTTPS_KNOWN_HOSTS"
                .to_string(),
        )),
    }
}

/// Parse `sha256:<64 hex>` (or bare hex) into a pin.
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
    let hex_part = s.strip_prefix("sha256:").unwrap_or(s);
    let bytes = hex::decode(hex_part)
        .map_err(|_| Error::InvalidArgument(format!("bad fingerprint (want sha256:<hex>): {s}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::InvalidArgument(format!("fingerprint must be 32 bytes: {s}")))?;
    Ok(arr)
}

/// Find the pin for `host:port`, if any. A missing file means no pins; a
/// malformed or comment line is skipped, never an error (the file is
/// user-editable — the documented mismatch recovery is deleting a line).
pub fn lookup(file: &Path, host: &str, port: u16) -> Result<Option<[u8; 32]>> {
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::InvalidArgument(format!(
                "read pin file {}: {e}",
                file.display()
            )))
        }
    };
    let key = format!("{host}:{port}");
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once(' ') {
            if k == key {
                if let Ok(pin) = parse_fingerprint(v.trim()) {
                    return Ok(Some(pin));
                }
            }
        }
    }
    Ok(None)
}

/// Append a pin line (creating parent dirs and the file as needed).
pub fn record(file: &Path, host: &str, port: u16, pin: &[u8; 32]) -> Result<()> {
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::InvalidArgument(format!("create {}: {e}", parent.display())))?;
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(file)
        .map_err(|e| Error::InvalidArgument(format!("open pin file {}: {e}", file.display())))?;
    writeln!(f, "{host}:{port} {}", scl_tlsio::fingerprint_hex(pin))
        .map_err(|e| Error::InvalidArgument(format!("write pin file {}: {e}", file.display())))?;
    Ok(())
}

/// One pin as stored: the `host:port` it was recorded for and its SPKI hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinEntry {
    pub host: String,
    pub port: u16,
    pub pin: [u8; 32],
}

/// A pin rendered as `sha256:<lowercase hex>`, the one fingerprint format.
pub fn fingerprint(pin: &[u8; 32]) -> String {
    scl_tlsio::fingerprint_hex(pin)
}

/// Parse `host`, `host:port` (the port defaults to
/// [`crate::http_transport::DEFAULT_PORT`]), the same split an `sc+https://`
/// URL's authority gets, so a pin names exactly what a connection looks up.
pub fn parse_host_port(s: &str) -> Result<(String, u16)> {
    let (host, port) = match s.split_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| Error::InvalidArgument(format!("bad port in {s:?}")))?,
        ),
        None => (s, crate::http_transport::DEFAULT_PORT),
    };
    if host.is_empty() {
        return Err(Error::InvalidArgument(format!("empty host in {s:?}")));
    }
    Ok((host.to_string(), port))
}

/// One non-comment line as a pin entry, if it is a well-formed one.
fn parse_line(line: &str) -> Option<PinEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, value) = line.split_once(' ')?;
    let (host, port) = key.split_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Some(PinEntry {
        host: host.to_string(),
        port,
        pin: parse_fingerprint(value.trim()).ok()?,
    })
}

fn read_pin_file(file: &Path) -> Result<String> {
    match std::fs::read_to_string(file) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(Error::InvalidArgument(format!(
            "read pin file {}: {e}",
            file.display()
        ))),
    }
}

/// Every well-formed pin in the file, in file order (a missing file is none;
/// comments and malformed lines are skipped). A host that was pinned twice is
/// listed twice: a connection uses the first.
pub fn list(file: &Path) -> Result<Vec<PinEntry>> {
    Ok(read_pin_file(file)?
        .lines()
        .filter_map(parse_line)
        .collect())
}

/// Drop every pin for `host:port` (hostnames compare case-insensitively) and
/// leave every other line, comments and malformed ones included, as it was.
/// Returns how many pins were removed; the file is only rewritten when it was
/// more than none, and atomically.
pub fn forget(file: &Path, host: &str, port: u16) -> Result<usize> {
    let text = read_pin_file(file)?;
    let (kept, removed) = without_pins(&text, host, port);
    if removed > 0 {
        write_pin_file(file, &kept)?;
    }
    Ok(removed)
}

/// Pin `host:port` to `pin`, replacing any pin it had. Returns whether one was
/// replaced.
pub fn set_pin(file: &Path, host: &str, port: u16, pin: &[u8; 32]) -> Result<bool> {
    let text = read_pin_file(file)?;
    let (mut kept, removed) = without_pins(&text, host, port);
    if !kept.is_empty() && !kept.ends_with('\n') {
        kept.push('\n');
    }
    kept.push_str(&format!(
        "{host}:{port} {}\n",
        scl_tlsio::fingerprint_hex(pin)
    ));
    write_pin_file(file, &kept)?;
    Ok(removed > 0)
}

fn without_pins(text: &str, host: &str, port: u16) -> (String, usize) {
    let mut kept = String::with_capacity(text.len());
    let mut removed = 0;
    for line in text.split_inclusive('\n') {
        match parse_line(line) {
            Some(e) if e.port == port && e.host.eq_ignore_ascii_case(host) => removed += 1,
            _ => kept.push_str(line),
        }
    }
    (kept, removed)
}

fn write_pin_file(file: &Path, text: &str) -> Result<()> {
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::InvalidArgument(format!("create {}: {e}", parent.display())))?;
    }
    scl_core::fsutil::atomic_write_durable(file, text.as_bytes())
        .map_err(|e| Error::InvalidArgument(format!("write pin file {}: {e}", file.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("scl-pins-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn record_then_lookup_round_trips() {
        let dir = tmp("rt");
        let file = dir.join("known_hosts");
        let pin = [0x11u8; 32];
        assert_eq!(lookup(&file, "example.com", 8730).unwrap(), None);
        record(&file, "example.com", 8730, &pin).unwrap();
        assert_eq!(lookup(&file, "example.com", 8730).unwrap(), Some(pin));
        // Same host, different port = a different pin slot.
        assert_eq!(lookup(&file, "example.com", 9000).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn pin_file_line_format_is_host_port_sha256_hex() {
        let dir = tmp("fmt");
        let file = dir.join("known_hosts");
        record(&file, "h", 8730, &[0xaa; 32]).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        assert_eq!(text, format!("h:8730 sha256:{}\n", "aa".repeat(32)));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn lookup_ignores_malformed_lines_and_comments() {
        let dir = tmp("junk");
        let file = dir.join("known_hosts");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&file, "# comment\n\nnot a pin line\nh:1 sha256:zz\n").unwrap();
        assert_eq!(lookup(&file, "h", 1).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn strict_from_fails_closed_on_unrecognized_values() {
        assert!(strict_from(Some("1")));
        assert!(strict_from(Some("true")));
        assert!(!strict_from(Some("0")));
        assert!(!strict_from(Some("")));
        assert!(!strict_from(None));
    }

    #[test]
    fn parse_fingerprint_accepts_both_forms_and_rejects_junk() {
        let hexs = "ab".repeat(32);
        let expected = [0xabu8; 32];
        assert_eq!(
            parse_fingerprint(&format!("sha256:{hexs}")).unwrap(),
            expected
        );
        assert_eq!(parse_fingerprint(&hexs).unwrap(), expected);
        assert!(parse_fingerprint("sha256:short").is_err());
        assert!(parse_fingerprint("md5:abcd").is_err());
        assert!(parse_fingerprint("").is_err());
    }

    #[test]
    fn list_forget_and_set_pin_manage_the_file() {
        let dir = tmp("manage");
        let file = dir.join("known_hosts");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &file,
            format!(
                "# mine\nA.example:8730 sha256:{}\nnot a pin\nb.example:9000 sha256:{}\nA.example:8730 sha256:{}\n",
                "11".repeat(32),
                "22".repeat(32),
                "33".repeat(32)
            ),
        )
        .unwrap();
        let entries = list(&file).unwrap();
        assert_eq!(entries.len(), 3, "a host pinned twice is listed twice");
        assert_eq!(entries[1].host, "b.example");
        assert_eq!(entries[1].port, 9000);

        // Forget is case-insensitive on the host, port-exact, removes every
        // pin for the slot, and leaves other lines (comments, junk) alone.
        assert_eq!(forget(&file, "a.EXAMPLE", 9000).unwrap(), 0);
        assert_eq!(forget(&file, "a.EXAMPLE", 8730).unwrap(), 2);
        let text = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            text,
            format!(
                "# mine\nnot a pin\nb.example:9000 sha256:{}\n",
                "22".repeat(32)
            )
        );
        assert_eq!(forget(&file, "gone", 1).unwrap(), 0);
        assert_eq!(
            forget(&dir.join("nope"), "h", 1).unwrap(),
            0,
            "no file, no pins"
        );

        // set_pin replaces and appends; the connection path sees the new pin.
        assert!(set_pin(&file, "b.example", 9000, &[0x44; 32]).unwrap());
        assert!(!set_pin(&file, "c.example", 8730, &[0x55; 32]).unwrap());
        assert_eq!(lookup(&file, "b.example", 9000).unwrap(), Some([0x44; 32]));
        assert_eq!(lookup(&file, "c.example", 8730).unwrap(), Some([0x55; 32]));
        assert_eq!(list(&file).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn set_pin_creates_the_file_and_a_missing_final_newline_is_handled() {
        let dir = tmp("create");
        let file = dir.join("sub").join("known_hosts");
        assert!(!set_pin(&file, "h", 1, &[0x66; 32]).unwrap());
        assert_eq!(list(&file).unwrap().len(), 1);
        std::fs::write(&file, "x:1 sha256:zz").unwrap(); // no trailing newline
        set_pin(&file, "h", 1, &[0x66; 32]).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.starts_with("x:1 sha256:zz\nh:1 sha256:"), "{text:?}");
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn parse_host_port_defaults_the_port_and_rejects_junk() {
        assert_eq!(parse_host_port("h").unwrap(), ("h".into(), 8730));
        assert_eq!(parse_host_port("h:9").unwrap(), ("h".into(), 9));
        assert!(parse_host_port("").is_err());
        assert!(parse_host_port(":9").is_err());
        assert!(parse_host_port("h:notaport").is_err());
        assert!(parse_host_port("h:99999").is_err());
    }
}
