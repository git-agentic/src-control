//! Create a secret file readable by its owner only, from the first byte (#214,
//! #281).
//!
//! One implementation for every secret file `sc` writes: `.sc/local-key`
//! (`scl-repo`), the `sc keygen` identity (`scl-cli`) and the TLS serve key
//! (`scl-tlsio`, which receives [`create_new_owner_only_or_warn`] from its
//! caller because it may not depend on a workspace crate).
//!
//! * unix: `create_new` with mode `0o600`.
//! * Windows: a protected single-ACE DACL for the current user, applied
//!   atomically by `CreateFileW` (`winacl.rs`, the only `unsafe`).
//! * other targets: [`io::ErrorKind::Unsupported`].

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Create `path`, failing with `AlreadyExists` if present, readable and
/// writable by the current user only. Never falls back to wider permissions:
/// an error means no file was created. Callers that prefer a degraded file to
/// a failure use [`create_new_owner_only_or_warn`].
pub fn create_new_owner_only(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        crate::winacl::create_new_owner_only(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Like [`create_new_owner_only`], but where the owner-only create fails for a
/// reason other than `AlreadyExists` (Windows ACL call failed, or an
/// unsupported target), create the file with default permissions instead and
/// print a one-time warning naming it. The operation still proceeds (the key
/// must be written), but the operator is told the file is unprotected. On unix this is exactly
/// [`create_new_owner_only`]: there is nothing to degrade to.
pub fn create_new_owner_only_or_warn(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        create_new_owner_only(path)
    }
    #[cfg(not(unix))]
    {
        with_default_fallback(create_new_owner_only(path), path, &WARNED)
    }
}

/// Once-per-process guard for the fallback warning.
#[cfg(not(unix))]
static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The fallback decision, separate from the platform call so unix tests can
/// drive it with an injected `restricted` result. `AlreadyExists` and success
/// pass through; any other error creates `path` with default permissions and
/// warns once via `warned`.
#[cfg(any(not(unix), test))]
fn with_default_fallback(
    restricted: io::Result<File>,
    path: &Path,
    warned: &std::sync::atomic::AtomicBool,
) -> io::Result<File> {
    match restricted {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
            let f = OpenOptions::new().write(true).create_new(true).open(path)?;
            if !warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "warning: could not restrict {} to its owner ({e}); it was created \
                     with default permissions and other local users may be able to read it",
                    path.display()
                );
            }
            Ok(f)
        }
        r => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("scl-core-owner-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn creates_once_and_refuses_an_existing_file() {
        let d = tmp("once");
        let p = d.join("secret");
        create_new_owner_only(&p)
            .unwrap()
            .write_all(b"s3cret")
            .unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"s3cret");
        let again = create_new_owner_only_or_warn(&p).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&p).unwrap(), b"s3cret", "never clobbered");
        std::fs::remove_dir_all(&d).unwrap();
        assert!(!d.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("mode");
        let p = d.join("secret");
        create_new_owner_only_or_warn(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn failed_owner_only_create_falls_back_and_warns_once() {
        let d = tmp("fallback");
        let warned = AtomicBool::new(false);
        let denied = || Err(io::Error::from(io::ErrorKind::PermissionDenied));

        let p = d.join("a");
        with_default_fallback(denied(), &p, &warned).unwrap();
        assert!(p.exists(), "fallback must still create the file");
        assert!(warned.load(Relaxed), "warned at creation");

        // A concurrent creator's AlreadyExists is not a protection failure.
        let warned = AtomicBool::new(false);
        let exists = Err(io::Error::from(io::ErrorKind::AlreadyExists));
        let r = with_default_fallback(exists, &d.join("b"), &warned);
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert!(!d.join("b").exists() && !warned.load(Relaxed));

        // If the default create fails too, that error surfaces unwarned.
        let r = with_default_fallback(denied(), &p, &warned);
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert!(!warned.load(Relaxed));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Windows: exactly one explicit, non-inherited full-control ACE for the
    /// current user, read back with `icacls`.
    #[cfg(windows)]
    fn assert_owner_only_dacl(path: &Path) {
        let out = std::process::Command::new("icacls")
            .arg(path)
            .output()
            .unwrap();
        assert!(out.status.success(), "icacls failed: {out:?}");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let acl = text.replace(path.to_str().unwrap(), "");
        let aces: Vec<&str> = acl.lines().filter(|l| l.contains(":(")).collect();
        let user = std::env::var("USERNAME").unwrap().to_lowercase();
        assert_eq!(aces.len(), 1, "exactly one ACE expected:\n{text}");
        let ace = aces[0].trim().to_lowercase();
        assert!(
            ace.contains(&format!("\\{user}:(")) && ace.contains("(f)") && !ace.contains("(i)"),
            "ACE must be an explicit full-control grant to {user}:\n{text}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_dacl_is_owner_only_and_owner_can_use_it() {
        let d = tmp("acl");
        let p = d.join("secret");
        create_new_owner_only(&p)
            .expect("ACL path must work on the CI host")
            .write_all(b"k")
            .unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"k", "owner can still read it");
        assert_owner_only_dacl(&p);
        let again = create_new_owner_only(&p).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Windows: a path past MAX_PATH still takes the ACL path (no fallback).
    #[cfg(windows)]
    #[test]
    fn windows_acl_applies_to_a_path_over_260_chars() {
        let top = tmp("long");
        let mut dir = top.clone();
        while dir.as_os_str().len() < 280 {
            dir.push("d".repeat(40));
        }
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("secret");
        assert!(p.as_os_str().len() > 260);
        create_new_owner_only(&p).expect("long path must still get the ACL");
        assert!(p.exists());
        std::fs::remove_dir_all(&top).unwrap();
    }
}
