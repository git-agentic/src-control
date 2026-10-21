//! `sc keygen --out` must never overwrite an existing identity, on any
//! platform: the seed cannot be regenerated (#214 review).

use std::process::Command;

#[test]
fn keygen_refuses_to_overwrite_an_existing_identity() {
    let dir = std::env::temp_dir().join(format!("scl-cli-keygen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let id = dir.join("alice.id");
    let keygen = || {
        Command::new(env!("CARGO_BIN_EXE_sc"))
            .args(["keygen", "--out", id.to_str().unwrap()])
            .current_dir(&dir)
            .output()
            .expect("sc runs")
    };

    assert!(keygen().status.success());
    let first = std::fs::read(&id).unwrap();

    let again = keygen();
    assert!(!again.status.success(), "second keygen must fail");
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("refusing to overwrite"),
        "{again:?}"
    );
    assert_eq!(std::fs::read(&id).unwrap(), first, "identity untouched");

    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!dir.exists());
}

/// Windows: the identity file is created with a single explicit, non-inherited
/// full-control ACE for the current user, read back with `icacls` (#281). On
/// unix it is 0600.
#[test]
fn keygen_identity_file_is_owner_only() {
    let dir = std::env::temp_dir().join(format!("scl-cli-keygen-acl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let id = dir.join("alice.id");
    let out = Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(["keygen", "--out", id.to_str().unwrap()])
        .current_dir(&dir)
        .output()
        .expect("sc runs");
    assert!(out.status.success(), "{out:?}");
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("warning"),
        "no fallback warning expected: {out:?}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&id).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    #[cfg(windows)]
    {
        let out = Command::new("icacls").arg(&id).output().unwrap();
        assert!(out.status.success(), "icacls failed: {out:?}");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let acl = text.replace(id.to_str().unwrap(), "");
        let aces: Vec<&str> = acl.lines().filter(|l| l.contains(":(")).collect();
        let user = std::env::var("USERNAME").unwrap().to_lowercase();
        assert_eq!(aces.len(), 1, "exactly one ACE expected:\n{text}");
        let ace = aces[0].trim().to_lowercase();
        assert!(
            ace.contains(&format!("\\{user}:(")) && ace.contains("(f)") && !ace.contains("(i)"),
            "ACE must be an explicit full-control grant to {user}:\n{text}"
        );
    }

    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!dir.exists());
}
