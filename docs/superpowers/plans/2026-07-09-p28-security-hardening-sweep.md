# P28 — Security Hardening Sweep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the four fix-now security-audit dispositions — ref-name validation, DoS caps, a `sc protect` nudge, and secret env-var hardening — as a P21-shaped sweep (spec: `docs/superpowers/specs/2026-07-09-security-hardening-design.md` Decisions 2–5; ADR-0039). First phase of the security horizon; P29 (sc+http access control) follows.

**Architecture:** Each item is a small, independent, security-only change to existing code. No new feature axis, no new user command, no new dependency. The demoable outcome is P21's: each audit repro becomes a pinned regression test while every existing demo stays green — this phase ships no new demo script.

**Tech Stack:** Rust stable, existing crates, **no new dependencies**.

## Global Constraints

- Security-only, no new feature axis, **no new dependency** (spec).
- Faithful build of the already-decided designs (spec Decisions 2–5 + ADR-0039) — do NOT re-open a settled decision.
- Every audit repro becomes a pinned regression test; every existing demo (ssh/http/streaming/sparse/provenance/history/protected-merge/partial-clone) stays green (spec).
- Tests next to code; disk tests clean up and assert removal (CLAUDE.md).

---

### Task 1: Remote UpdateRef ref-name validation (+ ROADMAP flip)

**Files:**
- Modify: `crates/repo/src/refs.rs` (guard `write_branch_tip` + `read_branch_tip`; upgrade `is_unsafe_ref_component`)
- Modify: `crates/repo/src/repo.rs` (expose/move `validate_branch_name` so refs.rs can call it — it is `pub(crate)` in repo.rs today; either `pub(crate) use` it into refs, or move the fn to refs.rs and have repo.rs re-import — pick the smaller diff, state it)
- Modify: `ROADMAP.md` (flip Active to P28; mirror the P25/P27 Task-1 flip; note the security horizon P28 sweep + P29 access control)

**The two validators — do NOT conflate them:**
- **Local branch writes** (`write_branch_tip` → `refs/heads/<name>`): use the STRICT `validate_branch_name` (rejects empty, `.`/`..`, leading-dot, `/`, `\`, whitespace, control). A local branch is a single component; this also protects the space-delimited oplog. This is the choke point the wire `UpdateRef` (`LocalTransport::update_ref` → `write_branch_tip`) reaches.
- **Remote-tracking writes** (`write_remote_tip` → `refs/remotes/<remote>/<branch>`): keep the existing `is_unsafe_ref_component` (it deliberately allows `/` for nested branch names) but UPGRADE it to ALSO reject whitespace/control (the oplog-corruption gap found while resolving — a hostile git remote's branch name).

- [ ] **Step 1: ROADMAP flip.**
- [ ] **Step 2: Failing tests** (refs.rs in-module + a transport/wire test):
  - `write_branch_tip_rejects_unsafe_names` (refs.rs): for each of `"../evil"`, `"a/b"`, `"has space"`, `"ctrl\u{7}"`, `".hidden"`, `""` → `write_branch_tip(&layout, name, &id)` returns `Err(BadRef)` and NO file is written under `refs/heads/`; a legit `"feature"` succeeds.
  - `read_branch_tip_rejects_unsafe_names` (refs.rs): `read_branch_tip(&layout, "../etc/passwd")` → `Err(BadRef)`, not a filesystem read.
  - `is_unsafe_ref_component_rejects_whitespace_and_control` (refs.rs): `is_unsafe_ref_component("has space")` and `"...\u{9}..."` and a control char → true; a normal `"origin"`/`"feature/x"` → false (nested `/` still allowed).
  - `wire_update_ref_rejects_traversal` (transport.rs or wire.rs tests): drive a `Transport::update_ref` (or the serve UpdateRef arm) with branch `"../../escape"` and `"has space"` → `Err(BadRef)`; no ref file created outside `refs/heads/`.
  - `remote_tracking_write_rejects_whitespace_branch` (refs.rs): `write_remote_tip(&layout, "origin", "bad name", &id)` → `Err(BadRef)`.
- [ ] **Step 3: Implement.** In `refs.rs`: `write_branch_tip` and `read_branch_tip` call `validate_branch_name(branch)?` at the top (before any path join / fs op). Make `validate_branch_name` reachable (grep its `pub(crate)` def at repo.rs:1554 — `pub(crate) use crate::repo::validate_branch_name;` in refs.rs, or move it — state the choice; keep `Repo::branch`'s existing calls, now redundant belt-and-suspenders). Upgrade `is_unsafe_ref_component` (refs.rs:97) to add `|| s.chars().any(|c| c.is_whitespace() || c.is_control())`.
- [ ] **Step 4: Run** `cargo test -p scl-repo` + `cargo test` + `bash demo/run_ssh_remote_demo.sh` + `bash demo/run_git_remote_demo.sh` → green (existing ref/branch/undo/ws tests undisturbed; legit branch names like `work-<i>` still valid). **Step 5: Commit** — `git commit -am "fix(repo): validate ref names at the write/read boundary — hostile wire UpdateRef + git-remote branch names rejected (P28)"`

---

### Task 2: DoS caps on untrusted lengths

**Files:**
- Modify: `crates/core/src/lib.rs` or a suitable core module (add `pub const MAX_OBJECT_SIZE: usize`)
- Modify: `crates/core/src/pack.rs` (`parse_pack_reader`: cap record `compressed_len` + bound the zstd output)
- Modify: `crates/core/src/object.rs` (four `Vec::with_capacity(n)` sites → `Reader::count()`)
- Modify: `crates/repo/src/wire.rs` (`read_frame_inner`: cap frame `len`)

**Interfaces:**
```rust
// core: the single anchor — the largest single object the system accepts.
pub const MAX_OBJECT_SIZE: usize = 256 * 1024 * 1024; // 256 MiB
```

- [ ] **Step 1: Failing tests:**
  - `frame_over_cap_rejected` (wire.rs): construct a frame header with `len = MAX_OBJECT_SIZE + 1`; `read_frame_inner` returns `Err(Protocol)` BEFORE allocating (feed only the 4-byte header — a bounded reader — and assert the error, not a hang/OOM).
  - `pack_record_over_cap_rejected` (pack.rs): a pack whose record `compressed_len` claims `MAX_OBJECT_SIZE + 1` → `parse_pack_reader` errors before `vec![0u8; len]`.
  - `zstd_bomb_rejected` (pack.rs): a record whose small compressed payload decompresses beyond `MAX_OBJECT_SIZE` → error (bound the decode output; do NOT decode unbounded then check).
  - `object_decode_fabricated_counts_rejected` (object.rs): a Tree with a fabricated huge entry count, a Snapshot with huge parents count, a Secret registry with huge count, a Signature with huge wrapped-keys count → each `Object::decode` returns `Err(Malformed)` (via `Reader::count()`), not an OOM. (Reuse the existing `count()` test idiom.)
- [ ] **Step 2: Implement.**
  - `MAX_OBJECT_SIZE` const in core.
  - `wire::read_frame_inner`: after reading `len`, `if len > scl_core::MAX_OBJECT_SIZE { return Err(Error::Protocol(...)) }` before `vec![0u8; len]`.
  - `pack::parse_pack_reader`: after reading a record's `compressed_len`, reject `> MAX_OBJECT_SIZE` before allocating; for the zstd output, decode with a bound — use `zstd::stream::read::Decoder` and `.take(MAX_OBJECT_SIZE as u64 + 1)` into a Vec, then error if the read hit the +1 (output exceeded the cap). (No new dep — `zstd` is already used.)
  - `object.rs`: the four `Vec::with_capacity(n as usize)` sites (tree entries ~328, snapshot parents ~353, secrets ~340, signature wrapped-keys ~407) — replace the raw `r.u32()?` + `with_capacity(n as usize)` with `let n = r.count()?; Vec::with_capacity(n)` (the guard rejects a count exceeding remaining bytes). Keep the loop bound consistent with `n`.
- [ ] **Step 3: Run** `cargo test -p scl-core -p scl-repo` + `cargo test` + `bash demo/run_streaming_demo.sh` + `bash demo/run_ssh_remote_demo.sh` → green (legit large-but-≤cap transfers unaffected; the streaming demo's chunked transfer undisturbed). **Step 4: Commit** — `git commit -am "fix(core,repo): MAX_OBJECT_SIZE caps frame/pack-record/zstd-output; object-decode counts use Reader::count() — untrusted-length DoS closed (P28)"`

---

### Task 3: `sc protect` pattern-aware nudge

**Files:**
- Modify: `crates/cli/src/main.rs` (`run_protect` ~2749 — emit the nudge; strengthen the `Protect` help doc-comment)

**Interfaces:** consumes nothing from earlier tasks.

- [ ] **Step 1: Failing test** (cli tests or a repo-level helper — a pure `looks_like_low_entropy_secret(basename) -> bool` unit is the cleanest to pin):
  - `looks_like_low_entropy_secret_matches_and_misses`: `true` for `.env`, `.env.local`, `id_rsa`, `deploy.key`, `server.pem`, `aws_credentials`, `cert.p12`; `false` for `main.rs`, `README.md`, `lib/util.rs`. (A `#[test]` on the predicate fn — keeps the heuristic testable without driving full CLI output.)
- [ ] **Step 2: Implement.** Add `fn looks_like_low_entropy_secret(basename: &str) -> bool` (a small basename heuristic: match `.env` / `.env.*`, and extensions/stems `pem`/`key`/`p12`/`pfx`, `id_*`, `*credentials*`, `*secret*` — case-insensitive). In `run_protect`, after resolving the matched paths, if any matched path's basename hits the heuristic, print ONE stderr warning naming an example path: `warning: <path> looks like a low-entropy secret; convergent encryption (sc protect) is equality-confirmable — prefer 'sc secret' for API keys / .env / credentials (see ADR-0014).` Warning-only — does NOT block; protect proceeds. Strengthen the `Protect` command's doc-comment (main.rs ~302) to mention the equality caveat + the `sc secret` steer. (Reuse or mirror the P5 scanner's sensibility, but this is a FILENAME heuristic, distinct from the scanner's content-regex — state that; do not run the content scanner here.)
- [ ] **Step 3: Run** `cargo test -p scl-cli` + `cargo test` + `bash demo/run_protected_merge_demo.sh` → green (protect still works; the nudge is stderr-only and doesn't change exit codes or the protected result). **Step 4: Commit** — `git commit -am "feat(cli): sc protect nudges low-entropy secret filenames toward sc secret (equality-caveat surfacing) (P28)"`

---

### Task 4: Secret env-var confidentiality — docs + zeroize verification

**Files:**
- Modify: `crates/repo/src/secrets.rs` (`secret_env` ~271–305 — ensure the decrypted plaintext stays `Zeroizing` through to the unavoidable `OsString` hand-off)
- Modify: `docs/adr/0008-committed-secrets-envelope-encryption.md` and/or `0009-*` (threat-model wording), `CLAUDE.md` (the secret/`sc run` note), `crates/cli/src/main.rs` (`Run` command help)

**Interfaces:** consumes nothing.

- [ ] **Step 1: GROUND FIRST (important nuance).** `scl_crypto::open` ALREADY returns `Zeroizing<Vec<u8>>` (crates/crypto/src/envelope.rs:57). So the decrypted plaintext is zeroized at the source. Read `secrets.rs::secret_env` and confirm the `plaintext` isn't copied into a plain `Vec`/`String` that outlives the `Zeroizing` before the `OsString` conversion. The child's `OsString` (which the kernel copies into the child env) is fundamentally un-zeroizable and stays documented — that is the accepted boundary, not a fix. Record in the report exactly what the current flow does and what (if anything) needs changing.
- [ ] **Step 2: Failing/assertion test** (secrets.rs tests): `secret_env_plaintext_is_zeroizing` — a compile-or-behavior assertion that the intermediate decrypted value is the `Zeroizing` type `open` returns (e.g. bind it explicitly as `let plaintext: scl_crypto::Zeroizing<Vec<u8>> = scl_crypto::open(...)?;` so a future refactor to a plain `Vec` fails to compile), and that a secret round-trips into the env correctly (existing `sc run` behavior unchanged). If Step 1 finds a plain-copy defeat, add a test that pins the fix; if the flow is already clean, this test locks it in.
- [ ] **Step 3: Implement.** Whatever Step 1 requires — likely: bind `open`'s result explicitly as `Zeroizing`, ensure the `OsStr::from_bytes(&plaintext).to_os_string()` reads directly from the `Zeroizing` buffer (no intermediate plain `Vec`), and drop `plaintext` promptly. If already clean, the code change is nil and this is a docs task. **Docs (the real deliverable):** in ADR-0008/0009's threat-model wording, CLAUDE.md's secret/`sc run` section, and the `Run` command help — state the boundary as **"authorized LOCAL PROCESS context, NOT strong isolation: the decrypted secret is observable by same-user processes, crash dumps, and shell wrappers through the child environment."**
- [ ] **Step 4: Run** `cargo test -p scl-repo` + `cargo test` + `bash demo/run_secret_demo.sh` (if present — else `sc secret-demo` via a demo) → green (secret injection behavior unchanged). **Step 5: Commit** — `git commit -am "docs+harden(repo): secret env-var boundary is authorized-local-process-context not isolation; plaintext stays Zeroizing to the env hand-off (P28)"`

---

### Task 5: Docs + ADR + horizon bookkeeping

**Files:**
- Modify: `docs/adr/0039-security-hardening-sweep.md` (→ Accepted + a code-verified refinements section), `docs/adr/README.md` (0039 → Accepted), `ROADMAP.md` (P28 → Done + BOTH a `## Done` narrative bullet AND the completed-phases table row; Active → "None — P29 sc+http access control is next up"; the deferred follow-ons to Deferred), `CLAUDE.md` (a `**Phase 28 is built.**` paragraph — the four hardening items + the accepted boundaries; no new command)

- [ ] **Step 1: Docs.** ADR-0039 → Accepted with a refinements section citing the exact fix sites (the two-validator split, `MAX_OBJECT_SIZE` placement + the zstd-bound mechanism, the filename heuristic, the `open`-already-returns-Zeroizing finding). ROADMAP: P28 Done (narrative bullet + table row); add the deferred follow-ons — **randomized protected mode**, **fd/stdin secret injection**, **`--max-object-size` config knob** — to the Deferred section; Active → P29 next. CLAUDE.md: `**Phase 28 is built.**` paragraph.
- [ ] **Step 2: Full verification** — `cargo test && bash demo/run_ssh_remote_demo.sh && bash demo/run_http_remote_demo.sh && bash demo/run_streaming_demo.sh && bash demo/run_sparse_demo.sh && bash demo/run_provenance_demo.sh && bash demo/run_history_demo.sh && bash demo/run_protected_merge_demo.sh && bash demo/run_partial_clone_demo.sh && git diff main -- '*Cargo.toml'` (all green; empty dep diff — NO new dependency; every prior demo is the regression gate for this security-only sweep; run_protect_demo.sh pre-P8 failure known — skip).
- [ ] **Step 3: Commit** — `git commit -am "docs: accept ADR-0039 security hardening sweep; P28 done (P28)"`
