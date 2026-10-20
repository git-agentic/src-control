//! `sc serve --max-conn-bytes` (#233, ADR-0039/0041 addenda): flag
//! parsing and bounds are checked at startup, and a real push over
//! `sc+http://` that exceeds the connection's write budget is refused with the
//! typed error while a push under it works.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

fn sc(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .env_remove("SC_MAX_OBJECT_SIZE")
        .env("SC_AUTHOR", "t")
        .output()
        .expect("sc runs")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-connbytes-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_http_server(root: &Path, extra: &[&str]) -> (Server, String) {
    let mut args = vec!["serve", "--http", "127.0.0.1:0"];
    args.extend_from_slice(extra);
    args.push(root.to_str().unwrap());
    let mut child = Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(&args)
        .env_remove("SC_MAX_OBJECT_SIZE")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn sc serve --http");
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    assert!(reader.read_line(&mut line).unwrap() > 0, "server announced");
    let addr = line
        .trim()
        .strip_prefix("listening on ")
        .unwrap_or_else(|| panic!("unexpected startup line: {line:?}"))
        .to_string();
    std::thread::spawn(move || for _ in reader.lines() {});
    (Server(child), addr)
}

#[test]
fn flag_is_parsed_and_bounds_checked_at_startup() {
    let root = tmp("flag");
    assert!(sc(&root, &["init"]).status.success());
    // Unparsable, below the object cap (default 256 MiB), and below an
    // explicit pack cap are all refused before serving.
    for (args, needle) in [
        (vec!["--max-conn-bytes", "x"], "--max-conn-bytes"),
        (vec!["--max-conn-bytes", "1.5MiB"], "--max-conn-bytes"),
        (vec!["--max-conn-bytes", "0"], "greater than zero"),
        (
            vec!["--max-conn-bytes", "1MiB"],
            "below the max object size (268435456)",
        ),
        (
            vec![
                "--max-object-size",
                "2MiB",
                "--max-pack-size",
                "8388608",
                "--max-conn-bytes",
                "4MiB",
            ],
            "below --max-pack-size",
        ),
    ] {
        let mut a = vec!["serve", "--stdio"];
        a.extend(&args);
        a.push(".");
        let o = sc(&root, &a);
        assert!(!o.status.success(), "{args:?} must be rejected");
        assert!(stderr(&o).contains(needle), "{args:?}: {}", stderr(&o));
    }
    std::fs::remove_dir_all(&root).unwrap();
    assert!(!root.exists());
}

#[test]
fn a_push_over_the_budget_is_refused_and_one_under_it_works() {
    // Unlimited pack cap so the connection budget is the binding limit.
    let server_dir = tmp("srv");
    assert!(sc(&server_dir, &["init"]).status.success());
    let (server, addr) = spawn_http_server(
        &server_dir,
        &[
            "--max-object-size",
            "2MiB",
            "--max-pack-size",
            "0",
            "--max-conn-bytes",
            "2MiB",
        ],
    );
    let url = format!("sc+http://{addr}");

    let client = tmp("cli");
    assert!(sc(&client, &["init"]).status.success());
    assert!(sc(&client, &["remote", "add", "origin", &url])
        .status
        .success());

    // Incompressible content so the spooled pack is about as big as the file.
    let noise = |len: usize| -> Vec<u8> {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    };
    std::fs::write(client.join("big.bin"), noise(3 * 1024 * 1024)).unwrap();
    assert!(sc(&client, &["commit", "-m", "big"]).status.success());
    let o = sc(&client, &["push", "origin"]);
    assert!(!o.status.success(), "3 MiB push exceeds a 2 MiB budget");
    let err = stderr(&o);
    assert!(
        err.contains("connection write budget exceeded") && err.contains("--max-conn-bytes"),
        "typed refusal names the knob: {err}"
    );

    let small = tmp("small");
    assert!(sc(&small, &["init"]).status.success());
    assert!(sc(&small, &["remote", "add", "origin", &url])
        .status
        .success());
    std::fs::write(small.join("a.txt"), "hello\n").unwrap();
    assert!(sc(&small, &["commit", "-m", "small"]).status.success());
    let o = sc(&small, &["push", "origin"]);
    assert!(
        o.status.success(),
        "a push under the budget works: {}",
        stderr(&o)
    );

    drop(server); // stop the listener before deleting its root
    for d in [server_dir, client, small] {
        std::fs::remove_dir_all(&d).unwrap();
        assert!(!d.exists());
    }
}
