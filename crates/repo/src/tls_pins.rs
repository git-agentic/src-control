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
    /// silently falling back to accept-new — see `strict_from`).
    pub strict: bool,
    /// `SC_HTTPS_CA_FILE` / `SC_HTTPS_CA=system` (ADR-0054): validate the
    /// server's certificate chain, validity and name against a CA instead of
    /// pinning. When set, the pin file is neither read nor written.
    pub ca: Option<CaSource>,
}

/// Where a CA-validated connection gets its trust anchors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaSource {
    /// A PEM bundle of CA certificates (`SC_HTTPS_CA_FILE`).
    File(PathBuf),
    /// The platform trust store (`SC_HTTPS_CA=system`).
    System,
}

/// Pure decision for the CA env knobs, factored out for the same reason as
/// [`strict_from`]. `file`/`mode` are the raw environment values (`None` =
/// the variable is absent). Fails closed: a security knob that is PRESENT but
/// empty (an unset shell variable in `SC_HTTPS_CA_FILE="$BUNDLE"`) or not
/// valid UTF-8 is an error, not an absence; so is an unrecognized `SC_HTTPS_CA`
/// value, both knobs at once, or CA trust together with a pre-pin. Nothing
/// here may quietly fall back to pinning or accept-new, which would send the
/// bearer token to an unverified host.
fn ca_from(
    file: Option<&std::ffi::OsStr>,
    mode: Option<&std::ffi::OsStr>,
    has_pre_pin: bool,
) -> Result<Option<CaSource>> {
    if file.is_some_and(|f| f.is_empty()) {
        return Err(Error::InvalidArgument(
            "SC_HTTPS_CA_FILE is set but empty; unset it or point it at a PEM bundle".to_string(),
        ));
    }
    let mode =
        match mode {
            None => None,
            Some(m) => Some(m.to_str().ok_or_else(|| {
                Error::InvalidArgument("SC_HTTPS_CA is not valid UTF-8".to_string())
            })?),
        };
    if mode.is_some_and(|m| m.is_empty()) {
        return Err(Error::InvalidArgument(
            "SC_HTTPS_CA is set but empty; use `system` or unset it".to_string(),
        ));
    }
    let source = match (file, mode) {
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => {
            return Err(Error::InvalidArgument(
                "set one of SC_HTTPS_CA_FILE and SC_HTTPS_CA, not both".to_string(),
            ))
        }
        (Some(f), None) => CaSource::File(PathBuf::from(f)),
        (None, Some("system")) => CaSource::System,
        (None, Some(other)) => {
            return Err(Error::InvalidArgument(format!(
                "SC_HTTPS_CA must be `system` (or use SC_HTTPS_CA_FILE=<pem>), got {other:?}"
            )))
        }
    };
    if has_pre_pin {
        return Err(Error::InvalidArgument(
            "SC_HTTPS_FINGERPRINT (a pin) cannot be combined with CA validation".to_string(),
        ));
    }
    Ok(Some(source))
}

impl TlsClientPolicy {
    pub fn from_env() -> Result<TlsClientPolicy> {
        // A pre-pin that is present but not valid UTF-8 is an error, not an
        // absent pin: ignoring it would drop an explicit trust decision (and
        // its conflict check with CA trust).
        let pre_pin = match std::env::var("SC_HTTPS_FINGERPRINT") {
            Ok(s) if !s.is_empty() => Some(parse_fingerprint(&s)?),
            Ok(_) | Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(Error::InvalidArgument(
                    "SC_HTTPS_FINGERPRINT is not valid UTF-8".to_string(),
                ))
            }
        };
        let strict = strict_from(std::env::var("SC_HTTPS_STRICT").ok().as_deref());
        let ca = ca_from(
            std::env::var_os("SC_HTTPS_CA_FILE").as_deref(),
            std::env::var_os("SC_HTTPS_CA").as_deref(),
            pre_pin.is_some(),
        )?;
        // CA mode never reads or writes the pin file, so a missing HOME (a
        // service, a container) must not fail it.
        let known_hosts = if ca.is_some() {
            known_hosts_path().unwrap_or_default()
        } else {
            known_hosts_path()?
        };
        Ok(TlsClientPolicy {
            known_hosts,
            pre_pin,
            strict,
            ca,
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
    let text = read_pin_file(file)?;
    // Hostnames are case-insensitive; the port is exact. A malformed or
    // comment line is skipped, never an error.
    Ok(text
        .lines()
        .filter_map(parse_line)
        .find(|e| e.port == port && e.host.eq_ignore_ascii_case(host))
        .map(|e| e.pin))
}

/// Append a pin line (creating parent dirs and the file as needed).
pub fn record(file: &Path, host: &str, port: u16, pin: &[u8; 32]) -> Result<()> {
    let file = resolve_pin_path(file);
    let file = file.as_path();
    let _lock = PinLock::acquire(file)?;
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
    writeln!(
        f,
        "{} {}",
        host_port(host, port),
        scl_tlsio::fingerprint_hex(pin)
    )
    .map_err(|e| Error::InvalidArgument(format!("write pin file {}: {e}", file.display())))?;
    Ok(())
}

/// An exclusive advisory lock on the pin file's sibling `<file>.lock`, held for
/// a whole read-modify-write (and for a first-connection append), so two `sc`
/// processes cannot lose each other's update or resurrect a forgotten pin.
/// `File::lock` is `flock` on unix and `LockFileEx` on Windows; the lock is
/// released when the guard drops.
struct PinLock {
    _file: std::fs::File,
}

impl PinLock {
    fn acquire(file: &Path) -> Result<PinLock> {
        let mut lock_path = file.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        if let Some(parent) = lock_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::InvalidArgument(format!("create {}: {e}", parent.display())))?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| {
                Error::InvalidArgument(format!("open pin lock {}: {e}", lock_path.display()))
            })?;
        f.lock()
            .map_err(|e| Error::InvalidArgument(format!("lock {}: {e}", lock_path.display())))?;
        Ok(PinLock { _file: f })
    }
}

/// Where a pin update really lands: a pin file that is a symlink (a shared or
/// dotfile-managed store) is followed, so the atomic rename replaces the target
/// and not the link. Anything else is returned as given.
fn resolve_pin_path(file: &Path) -> PathBuf {
    let is_link = std::fs::symlink_metadata(file).is_ok_and(|m| m.file_type().is_symlink());
    if !is_link {
        return file.to_path_buf();
    }
    if let Ok(real) = std::fs::canonicalize(file) {
        return real;
    }
    // A dangling link: write where it points.
    match std::fs::read_link(file) {
        Ok(target) if target.is_absolute() => target,
        Ok(target) => file.parent().unwrap_or(Path::new("")).join(target),
        Err(_) => file.to_path_buf(),
    }
}

/// `host` as it appears in a URL authority or `Host:` header: an IPv6 literal
/// gets its brackets back.
pub(crate) fn bracket_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// `host:port` with an IPv6 literal bracketed (`[::1]:7777`); the pin file's
/// key format and the display form.
pub fn host_port(host: &str, port: u16) -> String {
    format!("{}:{port}", bracket_host(host))
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
    let (host, port) = match crate::http_transport::split_authority(s) {
        Some((h, Some(p))) => (
            h,
            p.parse::<u16>()
                .map_err(|_| Error::InvalidArgument(format!("bad port in {s:?}")))?,
        ),
        Some((h, None)) => (h, crate::http_transport::DEFAULT_PORT),
        None => {
            return Err(Error::InvalidArgument(format!(
                "bad bracketed host in {s:?}"
            )))
        }
    };
    if host.is_empty() {
        return Err(Error::InvalidArgument(format!("empty host in {s:?}")));
    }
    // A host that a connection's URL authority could never produce would
    // yield a pin nothing looks up (or a line the reader takes for a comment).
    if host
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '/' || c == '#')
    {
        return Err(Error::InvalidArgument(format!(
            "bad host in {s:?}: no whitespace, '/' or '#'"
        )));
    }
    Ok((host.to_ascii_lowercase(), port))
}

/// One non-comment line as a pin entry, if it is a well-formed one.
fn parse_line(line: &str) -> Option<PinEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, value) = line.split_once(' ')?;
    // Same authority grammar as a URL: brackets must hold an IPv6 literal, so
    // a malformed key is skipped rather than read as a pin for another host.
    let (host, port) = crate::http_transport::split_authority(key)?;
    let port = port?.parse::<u16>().ok()?;
    Some(PinEntry {
        host,
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
    let file = resolve_pin_path(file);
    let file = file.as_path();
    let _lock = PinLock::acquire(file)?;
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
    let file = resolve_pin_path(file);
    let file = file.as_path();
    let _lock = PinLock::acquire(file)?;
    let text = read_pin_file(file)?;
    let (mut kept, removed) = without_pins(&text, host, port);
    if !kept.is_empty() && !kept.ends_with('\n') {
        kept.push('\n');
    }
    kept.push_str(&format!(
        "{} {}\n",
        host_port(host, port),
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
    // A bare relative name has an empty parent, which the durable write cannot
    // open to sync: anchor it at the current directory.
    let file: std::borrow::Cow<Path> = match file.parent() {
        Some(p) if p.as_os_str().is_empty() => Path::new(".").join(file).into(),
        _ => file.into(),
    };
    let file = file.as_ref();
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
    fn ipv6_literal_pins_round_trip_bracketed() {
        let dir = tmp("v6");
        let file = dir.join("known_hosts");
        let pin = [0x22u8; 32];
        record(&file, "::1", 7777, &pin).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        assert_eq!(text, format!("[::1]:7777 sha256:{}\n", "22".repeat(32)));
        assert_eq!(lookup(&file, "::1", 7777).unwrap(), Some(pin));
        assert_eq!(parse_host_port("[::1]:7777").unwrap(), ("::1".into(), 7777));
        assert_eq!(parse_host_port("[::1]").unwrap(), ("::1".into(), 8730));
        assert!(parse_host_port("[::1").is_err());
        assert_eq!(forget(&file, "::1", 7777).unwrap(), 1);
        assert_eq!(lookup(&file, "::1", 7777).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn pin_lines_follow_the_url_authority_grammar() {
        let hex = "ab".repeat(32);
        let line = |key: &str| parse_line(&format!("{key} sha256:{hex}"));
        // Brackets hold only an IPv6 literal, read in canonical form.
        assert_eq!(line("[::1]:7777").unwrap().host, "::1");
        assert_eq!(line("[0:0:0:0:0:0:0:1]:7777").unwrap().host, "::1");
        assert_eq!(line("example.com:8730").unwrap().host, "example.com");
        // Malformed keys are skipped, never read as a pin for another host.
        assert!(line("[example.com]:8730").is_none());
        assert!(line("[::1:7777").is_none());
        assert!(line("[::1]7777").is_none());
        assert!(line("[::1]").is_none(), "a port is required");
        assert!(line("::1:7777").is_none(), "unbracketed IPv6");
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

    #[test]
    fn lookup_matches_the_host_case_insensitively_and_the_port_exactly() {
        let dir = tmp("case");
        let file = dir.join("known_hosts");
        record(&file, "Example.COM", 8730, &[0x77; 32]).unwrap();
        assert_eq!(
            lookup(&file, "example.com", 8730).unwrap(),
            Some([0x77; 32])
        );
        assert_eq!(
            lookup(&file, "EXAMPLE.com", 8730).unwrap(),
            Some([0x77; 32])
        );
        assert_eq!(lookup(&file, "example.com", 8731).unwrap(), None);
        // A pin typed with any case is stored canonically, so a later lookup
        // (or a strict connect) under another case finds it.
        let (h, p) = parse_host_port("EXAMPLE.org:9").unwrap();
        assert_eq!((h.as_str(), p), ("example.org", 9));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn parse_host_port_rejects_hosts_no_connection_could_look_up() {
        for bad in [
            "example.com/repo",
            "a b",
            "#x",
            "x#y",
            "tab\there",
            "a\u{7}b",
        ] {
            assert!(parse_host_port(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_bare_relative_pin_file_works() {
        let dir = tmp("relative");
        std::fs::create_dir_all(&dir).unwrap();
        // Written through a relative name (empty parent), anchored at the cwd
        // by `write_pin_file`; the test uses an absolute path to the same effect
        // for the durable write, and checks the empty-parent branch directly.
        let rel = std::path::Path::new("scl-pins-relative-test-file");
        let _ = std::fs::remove_file(rel);
        set_pin(rel, "h", 1, &[0x88; 32]).unwrap();
        assert_eq!(lookup(rel, "h", 1).unwrap(), Some([0x88; 32]));
        assert_eq!(forget(rel, "h", 1).unwrap(), 1);
        let _ = std::fs::remove_file(rel);
        let _ = std::fs::remove_file("scl-pins-relative-test-file.lock");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Concurrent writers (threads stand in for processes: `flock` locks the
    /// open file description, and each update opens its own) never lose a pin.
    #[cfg(unix)]
    #[test]
    fn concurrent_pin_updates_lose_nothing() {
        let dir = tmp("concurrent");
        let file = dir.join("known_hosts");
        std::fs::create_dir_all(&dir).unwrap();
        let handles: Vec<_> = (0..16u16)
            .map(|i| {
                let file = file.clone();
                std::thread::spawn(move || {
                    set_pin(&file, &format!("h{i}.example"), 8730 + i, &[i as u8; 32]).unwrap();
                    record(&file, &format!("r{i}.example"), 8730, &[i as u8; 32]).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(list(&file).unwrap().len(), 32, "no update may be lost");
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    /// A pin file that is a symlink to a shared store: updates land in the
    /// target and the link survives.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_pin_file_is_updated_through_the_link() {
        let dir = tmp("symlink");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("shared_known_hosts");
        let link = dir.join("known_hosts");
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        set_pin(&link, "h.example", 1, &[0x99; 32]).unwrap();
        record(&link, "r.example", 2, &[0xaa; 32]).unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link must survive an update"
        );
        assert_eq!(list(&target).unwrap().len(), 2, "the target holds the pins");
        assert_eq!(forget(&link, "h.example", 1).unwrap(), 1);
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(list(&target).unwrap().len(), 1);

        // A dangling link is written through to where it points.
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(dir.join("not-yet"), &dangling).unwrap();
        set_pin(&dangling, "d.example", 3, &[0xbb; 32]).unwrap();
        assert_eq!(list(&dir.join("not-yet")).unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn ca_from_resolves_the_knobs_and_fails_closed() {
        use std::ffi::OsStr;
        let os = OsStr::new;
        assert_eq!(ca_from(None, None, false).unwrap(), None);
        assert_eq!(
            ca_from(Some(os("/etc/ca.pem")), None, false).unwrap(),
            Some(CaSource::File("/etc/ca.pem".into()))
        );
        assert_eq!(
            ca_from(None, Some(os("system")), false).unwrap(),
            Some(CaSource::System)
        );
        for bad in [
            ca_from(None, Some(os("yes")), false),
            ca_from(None, Some(os("System")), false),
            ca_from(Some(os("/x")), Some(os("system")), false),
            ca_from(None, Some(os("system")), true),
            ca_from(Some(os("/x")), None, true),
            // Present but empty: an unset shell variable, never an absence.
            ca_from(Some(os("")), None, false),
            ca_from(None, Some(os("")), false),
            ca_from(Some(os("")), Some(os("system")), false),
        ] {
            assert!(bad.is_err(), "must fail closed, got {bad:?}");
        }
    }

    /// A non-UTF-8 `SC_HTTPS_CA` must not read as "unset".
    #[cfg(unix)]
    #[test]
    fn ca_from_rejects_a_non_utf8_mode() {
        use std::os::unix::ffi::OsStrExt;
        let bad = std::ffi::OsStr::from_bytes(b"sys\xffem");
        assert!(ca_from(None, Some(bad), false).is_err());
    }
}
