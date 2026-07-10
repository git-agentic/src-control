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
        let known_hosts = match std::env::var_os("SC_HTTPS_KNOWN_HOSTS") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => default_known_hosts_path()?,
        };
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
}
