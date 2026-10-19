//! `sc tls` (ADR-0042 follow-on): list, forget and pin entries in the
//! `sc+https://` known_hosts file without editing it by hand.

use std::path::Path;
use std::process::Command;

fn sc(known_hosts: &Path, args: &[&str]) -> std::process::Output {
    // Run in the test-owned directory that holds the pin file.
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(known_hosts.parent().expect("pin file has a parent dir"))
        .env("SC_HTTPS_KNOWN_HOSTS", known_hosts)
        .output()
        .expect("sc runs")
}

fn out(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-tls-pins-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn pin_list_forget_round_trip_through_the_cli() {
    let dir = tmp("flow");
    let kh = dir.join("known_hosts");
    let fp_a = format!("sha256:{}", "ab".repeat(32));
    let fp_b = format!("sha256:{}", "cd".repeat(32));

    // Nothing pinned yet: a hint on stderr, no lines on stdout.
    let empty = sc(&kh, &["tls", "list"]);
    assert!(empty.status.success());
    assert_eq!(out(&empty), "");
    assert!(err(&empty).contains("no pins"), "{}", err(&empty));

    // Pin by host (default port) and by host:port.
    let o = sc(&kh, &["tls", "pin", "a.example", &fp_a]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("pinned a.example:8730"), "{}", out(&o));
    assert!(sc(&kh, &["tls", "pin", "b.example:9000", &fp_b])
        .status
        .success());
    let list = out(&sc(&kh, &["tls", "list"]));
    assert_eq!(
        list,
        format!("a.example:8730 {fp_a}\nb.example:9000 {fp_b}\n")
    );

    // JSON for scripts.
    let json = out(&sc(&kh, &["tls", "list", "--json"]));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["pins"][1]["host"], "b.example");
    assert_eq!(v["pins"][1]["port"], 9000);
    assert_eq!(v["pins"][1]["pin"], fp_b);

    // Re-pinning replaces, and says so.
    let re = sc(&kh, &["tls", "pin", "a.example", &fp_b]);
    assert!(out(&re).contains("re-pinned"), "{}", out(&re));
    assert_eq!(out(&sc(&kh, &["tls", "list"])).lines().count(), 2);

    // A host typed in another case is the same host.
    assert!(sc(&kh, &["tls", "pin", "C.Example:9001", &fp_a])
        .status
        .success());
    assert!(out(&sc(&kh, &["tls", "list"])).contains("c.example:9001"));
    assert!(sc(&kh, &["tls", "forget", "c.EXAMPLE:9001"])
        .status
        .success());

    // Forget removes that host's pin only; the other survives untouched.
    let f = sc(&kh, &["tls", "forget", "A.EXAMPLE"]);
    assert!(f.status.success(), "{}", err(&f));
    assert_eq!(
        out(&sc(&kh, &["tls", "list"])),
        format!("b.example:9000 {fp_b}\n")
    );

    // Forgetting what is not pinned is an error, not a silent success.
    let miss = sc(&kh, &["tls", "forget", "nope.example"]);
    assert!(!miss.status.success());
    assert!(
        err(&miss).contains("no pin for nope.example:8730"),
        "{}",
        err(&miss)
    );

    // `path` names the file in effect.
    assert_eq!(out(&sc(&kh, &["tls", "path"])).trim(), kh.to_str().unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!dir.exists());
}

#[test]
fn bad_input_is_refused_before_the_file_is_touched() {
    let dir = tmp("bad");
    let kh = dir.join("known_hosts");
    for args in [
        vec!["tls", "pin", "h", "not-a-fingerprint"],
        vec!["tls", "pin", "h", &format!("sha256:{}", "ab".repeat(31))],
        vec![
            "tls",
            "pin",
            ":9000",
            &format!("sha256:{}", "ab".repeat(32)),
        ],
        vec![
            "tls",
            "pin",
            "h:notaport",
            &format!("sha256:{}", "ab".repeat(32)),
        ],
        vec!["tls", "forget", "h:99999"],
        vec![
            "tls",
            "pin",
            "h/repo",
            &format!("sha256:{}", "ab".repeat(32)),
        ],
        vec!["tls", "pin", "a b", &format!("sha256:{}", "ab".repeat(32))],
    ] {
        let o = sc(&kh, &args);
        assert!(!o.status.success(), "{args:?} must be refused");
    }
    assert!(
        !kh.exists(),
        "a refused command must not create the pin file"
    );
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!dir.exists());
}
