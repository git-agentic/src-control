# P18 — Network Git Remotes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sc remote add/fetch/push/clone` work against hosted Git (GitHub over https/ssh) via a system-git mirror bridge (spec: `docs/superpowers/specs/2026-07-07-p18-network-git-remotes-design.md`, ADR-0028).

**Architecture:** A new `crates/gitio/src/bridge.rs` spawns the system `git` binary as transport only: it syncs a lazily-created bare mirror at `.sc/git-remotes/<name>/mirror.git` with the network URL. P10's existing import/export/marks/ff-gate machinery runs unchanged against the mirror path instead of a user-supplied local path. `sc clone <git-url>` composes init + remote add + fetch + unborn-branch adoption.

**Tech Stack:** Rust stable; `std::process` for the spawn (no new dependencies); `gix` stays quarantined in `crates/gitio`.

## Global Constraints

- The spawned `git` binary is **transport only** — object translation stays in-process `gix` in `crates/gitio`; the git binary never interprets sc state (spec).
- Auth fully delegated: no sc credential surface; spawned git's stderr passes through unmodified (spec).
- `SC_GIT` env var overrides the binary (the ADR-0022 `SC_SSH` pattern); a missing binary fails up front with a clear error naming the requirement (spec).
- `--git` stays required on `remote add` — bare `ssh://` means sc-native (ADR-0022); no URL auto-detection of remote kind (spec).
- Transport failures leave no partial sc-side state; the marks map survives them (spec).
- Mirror is reconstructible: deleting `.sc/git-remotes/<name>/` is safe; `sc gc` never touches it (spec).
- Integration tests and the demo use the REAL git binary over `file://` URLs (hermetic, no network/auth); `SC_GIT` shims are for failure injection only (spec).
- No new deps: `git diff -- '*Cargo.toml'` empty at the end of the phase.
- Tests live in `#[cfg(test)] mod tests` next to the code; disk tests clean up and assert removal (CLAUDE.md).

---

### Task 1: `gitio::bridge` — URL classification, spawn wrapper, mirror ops

**Files:**
- Create: `crates/gitio/src/bridge.rs`
- Modify: `crates/gitio/src/lib.rs` (add `pub mod bridge;`)
- Modify: `ROADMAP.md` (flip P18 to Active; Next-horizon table → P19–P20, following the P17 flip's exact shape)

**Interfaces:**
- Produces (all `pub` in `scl_gitio::bridge`, consumed by Tasks 2–3):
  - `fn is_network_git_url(url: &str) -> bool`
  - `fn ensure_mirror(mirror_dir: &Path, url: &str) -> anyhow::Result<PathBuf>` — creates/opens the bare mirror, pins `origin` to `url`, returns the mirror path
  - `fn mirror_fetch(mirror: &Path) -> anyhow::Result<()>` — `git fetch --prune origin "+refs/heads/*:refs/heads/*"` (force-syncs mirror heads; a stale post-push mirror head self-heals here)
  - `fn mirror_push(mirror: &Path, branch: &str) -> anyhow::Result<()>` — `git push origin refs/heads/<branch>:refs/heads/<branch>`
  - `fn remote_default_branch(mirror: &Path) -> anyhow::Result<String>` — parses `git ls-remote --symref origin HEAD`

- [ ] **Step 1: Flip P18 to Active in ROADMAP.md** (Active section names P18 + spec path; horizon table drops the P18 row and retitles P19–P20 — mirror the P17 flip, `git log --oneline --all -- ROADMAP.md` shows it).

- [ ] **Step 2: Write the failing tests**

`crates/gitio/src/bridge.rs` starts with its tests module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-bridge-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn classifies_network_git_urls() {
        for u in [
            "https://github.com/org/repo.git",
            "http://host/repo.git",
            "git@github.com:org/repo.git",
            "ssh://git@github.com/org/repo.git",
        ] {
            assert!(is_network_git_url(u), "{u} must classify as network");
        }
        for u in ["/abs/path/repo.git", "../rel/repo.git", "repo.git", "C:repo"] {
            assert!(!is_network_git_url(u), "{u} must classify as local");
        }
        // file:// is handled by the bridge (real-git transport) so demos/tests
        // exercise the genuine code path without a network.
        assert!(is_network_git_url("file:///tmp/hub.git"));
    }

    #[test]
    fn ensure_mirror_creates_bare_repo_pinned_to_url() {
        let root = tmp("ensure");
        // A real local bare repo as the "network" origin, via file://.
        let hub = root.join("hub.git");
        run_git(std::path::Path::new("."), &["init", "--bare", hub.to_str().unwrap()]).unwrap();
        let url = format!("file://{}", hub.display());

        let mirror_dir = root.join("mirror.git");
        let mirror = ensure_mirror(&mirror_dir, &url).unwrap();
        assert!(mirror.join("HEAD").exists(), "must be a bare git repo");
        // Idempotent + re-pins the URL.
        let mirror2 = ensure_mirror(&mirror_dir, &url).unwrap();
        assert_eq!(mirror, mirror2);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn fetch_and_push_round_trip_through_mirror() {
        let root = tmp("roundtrip");
        let hub = root.join("hub.git");
        run_git(std::path::Path::new("."), &["init", "--bare", hub.to_str().unwrap()]).unwrap();
        // Seed the hub with one commit via a scratch worktree.
        let seed = root.join("seed");
        run_git(std::path::Path::new("."), &["init", "-b", "main", seed.to_str().unwrap()]).unwrap();
        std::fs::write(seed.join("a.txt"), "hello").unwrap();
        run_git(&seed, &["add", "."]).unwrap();
        run_git(&seed, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "seed"]).unwrap();
        run_git(&seed, &["push", &format!("file://{}", hub.display()), "main"]).unwrap();

        let url = format!("file://{}", hub.display());
        let mirror = ensure_mirror(&root.join("mirror.git"), &url).unwrap();
        mirror_fetch(&mirror).unwrap();
        // The mirror now has the hub's head.
        let out = run_git_capture(&mirror, &["rev-parse", "refs/heads/main"]).unwrap();
        assert_eq!(out.trim().len(), 40, "mirror must have refs/heads/main");
        assert_eq!(remote_default_branch(&mirror).unwrap(), "main");

        // Write a second commit into the MIRROR's head (simulating P10 export),
        // push it up, and see it on the hub.
        let seed2 = root.join("seed2");
        run_git(std::path::Path::new("."), &["clone", mirror.to_str().unwrap(), seed2.to_str().unwrap()]).unwrap();
        std::fs::write(seed2.join("b.txt"), "world").unwrap();
        run_git(&seed2, &["add", "."]).unwrap();
        run_git(&seed2, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "two"]).unwrap();
        run_git(&seed2, &["push", "origin", "main"]).unwrap();
        mirror_push(&mirror, "main").unwrap();
        let hub_tip = run_git_capture(&hub, &["rev-parse", "refs/heads/main"]).unwrap();
        let mirror_tip = run_git_capture(&mirror, &["rev-parse", "refs/heads/main"]).unwrap();
        assert_eq!(hub_tip, mirror_tip, "push must land the mirror head on the hub");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sc_git_override_and_missing_binary_error() {
        let root = tmp("scgit");
        // A shim that always fails with a recognizable message.
        let shim = root.join("git-shim.sh");
        std::fs::write(&shim, "#!/bin/sh\necho 'shim: refusing' >&2\nexit 7\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();

        // SAFETY-of-test: env is process-global; keep the mutation scoped and
        // restore. (Mirror the SC_SSH test idiom in crates/repo — check
        // sync.rs/wire tests for the exact pattern used there and reuse it.)
        std::env::set_var("SC_GIT", shim.to_str().unwrap());
        let err = mirror_fetch(&root).unwrap_err();
        assert!(format!("{err:#}").contains("exit"), "shim exit must surface: {err:#}");

        std::env::set_var("SC_GIT", root.join("no-such-binary").to_str().unwrap());
        let err = mirror_fetch(&root).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("SC_GIT") || msg.contains("not found"), "missing binary must be a clear error: {msg}");
        std::env::remove_var("SC_GIT");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
```

- [ ] **Step 3: Run to verify failure** — `cargo test -p scl-gitio bridge` → FAIL (module missing until `pub mod bridge;` + items exist).

- [ ] **Step 4: Implement**

```rust
//! System-git mirror bridge (P18, ADR-0028): the spawned `git` binary is
//! TRANSPORT ONLY — it moves bytes between a local bare mirror and the
//! network. All object translation stays in-process (import/export in this
//! crate). Auth is entirely git's (ssh-agent, credential helpers); its
//! stderr passes through so failures read like git's own.

use std::path::{Path, PathBuf};
use std::process::Command;

/// True for URL forms that need the network bridge: https/http, scp-style
/// (`git@host:path`), ssh://, and file:// (bridged too, so tests and demos
/// drive the real transport code hermetically). Everything else is a local
/// path handled by the existing P10 direct machinery.
pub fn is_network_git_url(url: &str) -> bool {
    if url.starts_with("https://")
        || url.starts_with("http://")
        || url.starts_with("ssh://")
        || url.starts_with("file://")
    {
        return true;
    }
    // scp-style: user@host:path — an '@' and a ':' before any '/'.
    match (url.find('@'), url.find(':'), url.find('/')) {
        (Some(a), Some(c), slash) if a < c && slash.map_or(true, |s| c < s) => true,
        _ => false,
    }
}

fn git_program() -> String {
    std::env::var("SC_GIT").unwrap_or_else(|_| "git".to_string())
}

/// Spawn git with stderr inherited (auth prompts/errors reach the user
/// verbatim). Non-zero exit or a missing binary become clear errors.
fn run_git(dir: &Path, args: &[&str]) -> anyhow::Result<()> {
    let prog = git_program();
    let status = Command::new(&prog)
        .current_dir(dir)
        .args(args)
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "'{prog}' not found — network Git remotes require the git binary on PATH \
                 (or set SC_GIT to point at one)"
            ),
            _ => anyhow::anyhow!("spawning '{prog}': {e}"),
        })?;
    if !status.success() {
        anyhow::bail!("{prog} {} failed (exit {})", args.join(" "), status.code().unwrap_or(-1));
    }
    Ok(())
}

/// As `run_git`, but captures stdout (for rev-parse / ls-remote parsing).
fn run_git_capture(dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    let prog = git_program();
    let out = Command::new(&prog)
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "'{prog}' not found — network Git remotes require the git binary on PATH \
                 (or set SC_GIT to point at one)"
            ),
            _ => anyhow::anyhow!("spawning '{prog}': {e}"),
        })?;
    if !out.status.success() {
        std::io::Write::write_all(&mut std::io::stderr(), &out.stderr).ok();
        anyhow::bail!("{prog} {} failed (exit {})", args.join(" "), out.status.code().unwrap_or(-1));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Create (or open) the bare mirror for `url`, (re-)pinning its `origin`.
/// Idempotent; deleting the dir is always safe (next call recreates it).
pub fn ensure_mirror(mirror_dir: &Path, url: &str) -> anyhow::Result<PathBuf> {
    if !mirror_dir.join("HEAD").exists() {
        std::fs::create_dir_all(mirror_dir)?;
        run_git(mirror_dir, &["init", "--bare", "--quiet", "."])?;
        run_git(mirror_dir, &["remote", "add", "origin", url])?;
    } else {
        run_git(mirror_dir, &["remote", "set-url", "origin", url])?;
    }
    Ok(mirror_dir.to_path_buf())
}

/// Sync the mirror's heads from the network. The `+` refspec force-updates:
/// mirror heads are cache (a post-push mirror head that the remote later
/// rejected self-heals here), and `--prune` drops deleted branches.
pub fn mirror_fetch(mirror: &Path) -> anyhow::Result<()> {
    run_git(mirror, &["fetch", "--prune", "--quiet", "origin", "+refs/heads/*:refs/heads/*"])
}

/// Push one branch of the mirror up to the network remote. Non-ff rejections
/// come back as git's own error text.
pub fn mirror_push(mirror: &Path, branch: &str) -> anyhow::Result<()> {
    let spec = format!("refs/heads/{branch}:refs/heads/{branch}");
    run_git(mirror, &["push", "--quiet", "origin", &spec])
}

/// The remote's default branch (`HEAD` symref), e.g. "main".
pub fn remote_default_branch(mirror: &Path) -> anyhow::Result<String> {
    let out = run_git_capture(mirror, &["ls-remote", "--symref", "origin", "HEAD"])?;
    // First line: "ref: refs/heads/<name>\tHEAD"
    out.lines()
        .find_map(|l| l.strip_prefix("ref: refs/heads/"))
        .and_then(|rest| rest.split_whitespace().next())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("could not determine the remote's default branch (ls-remote --symref gave no HEAD symref)"))
}
```

Note: `scl-gitio` already depends on `anyhow` (`export.rs` returns `anyhow::Result`). ENV-RACE WARNING: cargo runs tests in parallel threads and `run_git` reads `SC_GIT` at call time, so the SC_GIT test would poison the OTHER spawning tests (`ensure_mirror…`, `fetch_and_push…`) mid-run. Guard with a shared lock — add to the tests module:

```rust
static GIT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
```

Every bridge test that spawns git takes `let _g = GIT_ENV_LOCK.lock().unwrap();` as its first line (the SC_GIT test included), so env mutation is serialized against all spawns. Use `.unwrap_or_else(|p| p.into_inner())` if a prior panic poisoned the lock. No new dependency.

- [ ] **Step 5: Run** — `cargo test -p scl-gitio` → PASS; `cargo test` → workspace green.

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(gitio): system-git mirror bridge — url classification, SC_GIT spawn wrapper, mirror fetch/push/default-branch (P18)"`

---

### Task 2: CLI routing — network URLs through the mirror on fetch/push

**Files:**
- Modify: `crates/cli/src/main.rs` (`run_remote` ~1550, `run_fetch_git` ~1603, `run_push_git` ~1657)

**Interfaces:**
- Consumes: all five `scl_gitio::bridge` functions (Task 1).
- Produces: `fn git_remote_effective_path(repo: &scl_repo::Repo, remote: &str, url: &str, sync_from_network: bool) -> Result<PathBuf>` — the single helper Tasks 2–3 share: for a network URL, ensure the mirror (at `repo.layout().dot_sc.join("git-remotes").join(remote).join("mirror.git")`) and optionally `mirror_fetch`; for a local path, pass it through untouched.

- [ ] **Step 1: Implement the helper + routing**

```rust
/// The local git path P10's import/export machinery should operate on for
/// `remote`: the URL itself when it is a local path, or the synced bare
/// mirror when it is a network URL (ADR-0028 bridge). `sync_from_network`
/// runs `git fetch` into the mirror first — wanted on sc fetch (fresh data)
/// and on clone; NOT on push (export goes into the mirror as-is; a stale
/// mirror head just means git push reports non-ff, verbatim).
fn git_remote_effective_path(
    repo: &scl_repo::Repo,
    remote: &str,
    url: &str,
    sync_from_network: bool,
) -> Result<std::path::PathBuf> {
    if !scl_gitio::bridge::is_network_git_url(url) {
        return Ok(std::path::PathBuf::from(url));
    }
    let mirror_dir = repo.layout().dot_sc.join("git-remotes").join(remote).join("mirror.git");
    let mirror = scl_gitio::bridge::ensure_mirror(&mirror_dir, url)?;
    if sync_from_network {
        scl_gitio::bridge::mirror_fetch(&mirror)?;
    }
    Ok(mirror)
}
```

Routing edits (surgical — P10's logic is otherwise untouched):
- `run_fetch_git`: after resolving `url`, insert `let path = git_remote_effective_path(repo, remote, &url, true)?;` and change the `import_history(..., std::path::Path::new(&url), ...)` call to use `&path`.
- `run_push_git`: insert `let path = git_remote_effective_path(repo, remote, &url, false)?;`; the ff-gate's `read_ref(std::path::Path::new(&url), …)` and the `ExportOptions { to: … }` both switch to `&path`; after the marks append (the very end of the success path), add:
```rust
if scl_gitio::bridge::is_network_git_url(&url) {
    scl_gitio::bridge::mirror_push(&path, &branch)?;
    println!("pushed {remote} -> network ({url})");
}
```
(Ordering note for the reviewer: export+marks precede the network push, mirroring P10's crash-analysis comment — a crash after export/marks but before `mirror_push` leaves the mirror ahead of the network, and the next `sc push` retries `mirror_push` idempotently. The stale-network-ff case is caught by git itself.)
- One caveat to fix in the same pass: `run_push_git`'s ff-gate reads the MIRROR ref, which reflects the last `sc fetch`. That is exactly the spec's semantics (ff-only at the sc layer against last-known state; the network's own non-ff rejection is authoritative) — add that sentence as a comment at the gate.
- `run_remote` / `RemoteOp::Add { git: true }`: validate up front — `if !scl_gitio::bridge::is_network_git_url(&url) && !std::path::Path::new(&url).join("HEAD").exists() && !std::path::Path::new(&url).join(".git").exists() { bail!("'{url}' is neither a git URL nor a local git repo") }` — and print `added git remote {name} -> {url}` (unchanged) plus `  (network: transport via the system git binary)` when it classifies network.

- [ ] **Step 2: Write the failing end-to-end test**

In `crates/cli/src/main.rs`'s tests module (this is a REAL-git integration test over `file://`; it drives the same functions the commands run — follow the module's existing test idioms for building a repo in a temp dir):

```rust
#[test]
fn network_git_remote_round_trip_over_file_url() {
    let root = std::env::temp_dir().join(format!("scl-cli-netgit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    // A bare hub reachable only through a file:// URL (network-shaped).
    let hub = root.join("hub.git");
    std::process::Command::new("git")
        .args(["init", "--bare", "-b", "main", hub.to_str().unwrap()])
        .status().unwrap();
    let url = format!("file://{}", hub.display());

    // sc repo with one commit.
    let work = root.join("repo");
    std::fs::create_dir_all(&work).unwrap();
    let repo = scl_repo::Repo::init(&work).unwrap();
    std::fs::write(work.join("readme.txt"), "hello").unwrap();
    repo.commit("me", "first").unwrap();
    repo.remote_add_git("origin", &url).unwrap();

    // Push through the mirror, then verify the HUB (not the mirror) has it.
    run_push_git(&repo, "origin", false).unwrap();
    let out = std::process::Command::new("git")
        .current_dir(&hub).args(["log", "--oneline"]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("first"),
        "commit must be visible on the hub via git log");

    // Fetch back through the mirror (round trip sanity).
    run_fetch_git(&repo, "origin").unwrap();

    drop(repo);
    std::fs::remove_dir_all(&root).unwrap();
}
```

- [ ] **Step 3: Run** — `cargo test -p scl-cli network_git` → PASS after Step 1 (write test first, watch it fail without the routing, then confirm); `cargo test` → green.

- [ ] **Step 4: Commit** — `git add -A && git commit -m "feat(cli): route network git remotes through the mirror bridge — fetch syncs first, push exports then pushes up (P18)"`

---

### Task 3: `sc clone <git-url> <dst>`

**Files:**
- Modify: `crates/cli/src/main.rs` (`run_clone` ~1528; new `fn run_clone_git(url: &str, dst: &Path) -> Result<()>`)

**Interfaces:**
- Consumes: `bridge::{is_network_git_url, remote_default_branch}`, `git_remote_effective_path` (Task 2), `run_fetch_git` (existing), `scl_repo::refs::write_head`, `Repo::{init, remote_add_git, merge}`.

- [ ] **Step 1: Implement**

In `run_clone`, branch first:

```rust
fn run_clone(src: String, dst: PathBuf) -> Result<()> {
    if scl_gitio::bridge::is_network_git_url(&src) {
        return run_clone_git(&src, &dst);
    }
    let repo = scl_repo::Repo::clone_url(&src, &dst)?;
    // … existing body unchanged …
}

/// Clone from a hosted Git URL: init + remote add origin --git + fetch +
/// adopt the remote's default branch (P10's unborn fast-forward adoption).
fn run_clone_git(url: &str, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    let repo = scl_repo::Repo::init(dst)?;
    repo.remote_add_git("origin", url)?;

    // Sync the mirror, then point the unborn HEAD at the remote's default
    // branch name BEFORE fetching, so the tracking ref and local branch agree.
    let mirror = git_remote_effective_path(&repo, "origin", url, true)?;
    let default = scl_gitio::bridge::remote_default_branch(&mirror)?;
    scl_repo::refs::write_head(repo.layout(), &default)?;

    run_fetch_git(&repo, "origin")?;
    // Adopt: merge the tracking ref into the unborn branch (ADR-0018's
    // unborn fast-forward). Author resolution mirrors run_merge's.
    let author = author_name(None); // ← use the SAME helper run_merge/run_commit use; check its exact name/signature first
    repo.merge(&format!("origin/{default}"), &author)?;
    println!("cloned {url} into {} (branch {default})", dst.display());
    Ok(())
}
```

IMPORTANT for the implementer: `author_name(None)` is a stand-in — find the actual author-resolution used by `run_commit`/`run_merge` (`grep -n "SC_AUTHOR" crates/cli/src/main.rs`) and call it identically. Also confirm `run_fetch_git` fetches the CURRENT branch (it does — it reads `refs::current_branch`), which is why HEAD must be re-pointed before the fetch, not after.

- [ ] **Step 2: Write + run the test**

```rust
#[test]
fn clone_from_network_git_url_adopts_default_branch() {
    let root = std::env::temp_dir().join(format!("scl-cli-gitclone-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    // Hub with default branch "trunk" and one seeded commit.
    let hub = root.join("hub.git");
    std::process::Command::new("git")
        .args(["init", "--bare", "-b", "trunk", hub.to_str().unwrap()]).status().unwrap();
    let seed = root.join("seed");
    std::process::Command::new("git").args(["init", "-b", "trunk", seed.to_str().unwrap()]).status().unwrap();
    std::fs::write(seed.join("a.txt"), "x").unwrap();
    for args in [vec!["add", "."], vec!["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "seed"]] {
        std::process::Command::new("git").current_dir(&seed).args(&args).status().unwrap();
    }
    std::process::Command::new("git").current_dir(&seed)
        .args(["push", &format!("file://{}", hub.display()), "trunk"]).status().unwrap();

    let dst = root.join("cloned");
    run_clone_git(&format!("file://{}", hub.display()), &dst).unwrap();
    let repo = scl_repo::Repo::open(&dst).unwrap();
    assert_eq!(scl_repo::refs::current_branch(repo.layout()).unwrap(), "trunk",
        "local branch must adopt the remote default name");
    assert!(dst.join("a.txt").exists(), "working tree must be materialized");
    drop(repo);
    std::fs::remove_dir_all(&root).unwrap();
}
```

(If `Repo::open` is spelled differently, mirror how other cli tests reopen a repo.) Run: `cargo test -p scl-cli clone_from_network` → PASS; `cargo test` → green.

- [ ] **Step 3: Commit** — `git add -A && git commit -m "feat(cli): sc clone <git-url> — init + remote add + fetch + default-branch adoption through the mirror bridge (P18)"`

---

### Task 4: Demo — `demo/run_network_git_demo.sh`

**Files:**
- Create: `demo/run_network_git_demo.sh` (mode 755)

- [ ] **Step 1: Write the script.** House style (read `demo/run_git_remote_demo.sh` first — this demo is its network-shaped sibling): `set -euo pipefail`, single `cargo build`, `fail()`, `mktemp -d` + trap, every claim asserted. Sequence:

1. Create a bare hub (`git init --bare -b main hub.git`), seed it with one commit via a scratch git worktree; `url="file://$hub"`.
2. `sc clone "$url" repo1` → assert current branch matches hub default, seeded file present.
3. Commit new work in repo1 (`sc commit`), `sc push origin` → assert `git -C hub.git log --oneline` shows the new message (the hub, not the mirror, is asserted — that's the network claim).
4. `sc clone "$url" repo2` → assert the new commit's file arrived.
5. In repo2, commit again, `sc push`; in repo1 `sc fetch origin` + `sc merge origin/main` → assert repo1 has repo2's file (full collaborative loop).
6. Assert mirror reconstructibility: `rm -rf repo1/.sc/git-remotes/origin` → `sc fetch origin` in repo1 still succeeds.
7. RESULT lines + print the real-GitHub recipe (`sc remote add origin git@github.com:org/repo.git --git`, auth note: ssh-agent/credential helpers, git-on-PATH requirement).

- [ ] **Step 2: Run it twice + the P10/P12 siblings** — `bash demo/run_network_git_demo.sh` (×2), `bash demo/run_git_remote_demo.sh`, `bash demo/run_ssh_remote_demo.sh` → all exit 0.

- [ ] **Step 3: Commit** — `git add demo/run_network_git_demo.sh && git commit -m "demo: network git round trip over file:// through the mirror bridge — clone, push, second clone, fetch/merge, mirror reconstruction (P18)"`

---

### Task 5: Docs — firm ADR-0028, ROADMAP, CLAUDE.md, ADR index

**Files:**
- Modify: `docs/adr/0028-network-git-remotes.md` (Status → Accepted + "Refinements discovered during the build" — every claim verified against code; the P16/P17 doc reviews both bounced imprecise prose, don't repeat it)
- Modify: `docs/adr/README.md` (0028 → Accepted)
- Modify: `ROADMAP.md` (P18 → Done + completed-phases row: goal "fetch/push against hosted Git", outcome "sc clone git@github.com:… / push visible on github.com; proven hermetically by demo/run_network_git_demo.sh"; Active → "None — Phase 19 is next up"; horizon table P19–P20)
- Modify: `CLAUDE.md` (Commands block: `sc clone <git-url> <dst>`, network forms on `remote add … --git`, `SC_GIT` override, git-on-PATH requirement for network remotes, demo line; a `**Phase 18 is built.**` paragraph in the established voice; "Remaining follow-ons" drops network Git remotes)

- [ ] **Step 1: Make the edits** (follow the P17 completion commit's shape — `git log --oneline --grep "accept ADR-0027"`).
- [ ] **Step 2: Full verification** — `cargo test && bash demo/run_network_git_demo.sh && bash demo/run_git_remote_demo.sh && bash demo/run_ssh_remote_demo.sh && git diff main -- '*Cargo.toml'` (expect: all green; empty dep diff). Known pre-existing failure in `demo/run_protect_demo.sh` (pre-P8) — do not chase.
- [ ] **Step 3: Commit** — `git add -A && git commit -m "docs: accept ADR-0028 network git remotes; record P18 across CLAUDE/ROADMAP/ADR index"`
