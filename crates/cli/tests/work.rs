//! End-to-end `sc work` through the real binary: init → commit → work →
//! merge, asserting the summary, the branches, and full cleanup.
use std::process::Command;

#[test]
fn sc_work_end_to_end() {
    let sc = env!("CARGO_BIN_EXE_sc");
    let base = std::env::temp_dir().join(format!("sc-cli-work-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(sc)
            .args(args)
            .current_dir(&base)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "sc {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    run(&["init"]);
    std::fs::write(base.join("a.txt"), "base\n").unwrap();
    run(&["commit", "-m", "base", "--author", "test"]);
    let summary = run(&[
        "work",
        "--agents",
        "2",
        "--author",
        "test",
        "--",
        "sh",
        "-c",
        "echo \"$SC_WORKSPACE\" > out.txt",
    ]);
    assert!(
        summary.contains("work-1"),
        "summary missing work-1:\n{summary}"
    );
    assert!(
        summary.contains("work-2"),
        "summary missing work-2:\n{summary}"
    );
    run(&["merge", "work-1", "--author", "test"]);
    assert_eq!(
        std::fs::read_to_string(base.join("out.txt")).unwrap(),
        "work-1\n"
    );
    std::fs::remove_dir_all(&base).unwrap();
    assert!(!base.exists());
}
