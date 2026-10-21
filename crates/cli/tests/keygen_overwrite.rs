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
