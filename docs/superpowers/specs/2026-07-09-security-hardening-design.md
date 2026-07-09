# Security hardening: design

**Date:** 2026-07-09
**Status:** Approved (ready for a build phase — brainstorm → plan → subagent-driven build)
**ADR:** to be assigned when the phase is built
**Source:** a 6-finding security audit (3 High, 3 Medium) delivered 2026-07-09, charted and dispositioned via the wayfinder map [Security hardening: audit findings → decided spec](https://github.com/git-agentic/src-control/issues/1) (issues #2–#9).

## Problem

A security audit surfaced six findings against src-control's network transport, ref
handling, object decode, protected-path crypto, and secret execution. Each needed a
decided disposition — fix-now, accept-and-document, or design-then-fix — and three
needed real design (sc+http access control, DoS caps, ref-name validation). This spec
records those decisions so a build phase can implement them without re-litigating.

**Excluded (stale):** the audit's "reachability test failing"
(`reachable::tests::in_filter_absent_is_an_error`) was run against a pre-`536c22b`
commit; it **passes on current main** — P27's final-review fix already makes an
in-filter-absent object surface as corruption. Not a real issue.

## Decision 1 — sc+http access control (posture + auth)

Three map decisions (posture #2, auth shape #7, auth detail #9) combine into one
coherent access-control story for `sc serve --http` (ADR-0036). **Disposition:
fix-now (posture) + design-then-fix (auth mechanism).**

### Read-only server mode

An opt-in `--read-only` flag threads through `serve_http`/`serve_http_listener` →
`wire::serve`. When set, the wire dispatch loop rejects the three mutating verbs —
`PutObject`, `PutPack`, `UpdateRef` — **before any store write**, returning a typed
"server is read-only" wire error the client surfaces. Reads (`ListRefs`,
`HeadBranch`, `HasObject`, `GetObject`, `GetPack`) stay allowed; `sc backfill` is a
client `GetPack`, so it works against a read-only server. All-or-nothing at the
server level; per-token granularity comes from auth (below).

### Bind posture — fail-closed

A non-loopback bind (anything but `127.0.0.0/8` / `::1` / `localhost`) is **refused**
unless one of three justifications holds: `--read-only`, an explicit `--allow-public`
override, **or token auth is enabled** (a token-required server is no longer
unauthenticated). Loopback binds always work. Every doc + CLI example uses
`127.0.0.1`, not `0.0.0.0`. Honest stance: `sc serve --http` is unauthenticated
*unless* tokens are configured; for TLS, front it with a reverse proxy.

### Auth mechanism — dep-free bearer tokens at the HTTP opening

Chosen over mTLS (which would be the project's first TLS dependency, against the
P25/P26 dep-free grain; TLS stays the fronting-proxy's job). **Zero new dependencies**
(BLAKE3 is already a dep; constant-time compare is std-implementable).

- **Where:** the check sits at the **HTTP opening**. Extend
  `http_transport::read_client_opening` to also parse the header block and surface the
  `Authorization: Bearer <token>` value (it already reads the full bounded opening).
  In `handle_http_connection`, when auth is configured, constant-time-compare
  `BLAKE3(presented token)` against stored hashes; miss/absent → `write_status(401)`
  and close, **before** the `200`/wire handoff (mirroring the existing 400/404
  pre-handshake pattern). The **wire protocol is unchanged** — so the ssh path (already
  authenticated by ssh) is untouched, and a reverse proxy can inject/validate the header.
- **Client:** presents the raw token via an `SC_HTTP_TOKEN` env var (the `SC_SSH`/
  `SC_GIT` pattern — no plaintext in argv/history).
- **Composition:** enabling auth **satisfies the fail-closed public-bind gate** (auth
  is the real `--allow-public`). When configured, a valid token is **required on every
  connection, loopback included** (no bypass).
- **Storage:** a dedicated `.sc/serve-tokens.toml` (server access-control is distinct
  from `recipients.toml`'s encryption/signing trust). Each entry:
  `{ label, hash = BLAKE3(raw token), scope = "ro" | "rw" }`. Tokens are high-entropy
  random — a plain hash suffices, no KDF/salt. The raw token is never persisted.
- **Scope enforcement:** a matched token's scope sets the connection's read-only flag,
  routing into the **same** mutating-verb rejection gate — a `ro` token behaves like
  `--read-only` for that connection; an `rw` token permits mutations.
- **Management:** `sc serve token add --label <n> --scope ro|rw` (generates a random
  token, prints the RAW token **once**, stores hash+label+scope), `sc serve token
  remove <label>`, `sc serve token list` (labels+scopes, never the token). Rotation =
  add-new + remove-old. Consistent with `sc keygen`/`sc secret`.

## Decision 2 — remote UpdateRef ref-name validation

The genuine, undocumented bug (audit High). `LocalTransport::update_ref` passes a
remote-supplied branch name straight to `refs::write_branch_tip`, which joins it under
`refs/heads/`, bypassing the CLI's `validate_branch_name`. A hostile wire client can
send `../…`, `/`-bearing, whitespace, control-char, or leading-dot names.
**Disposition: fix-now.**

- Apply the strict `validate_branch_name` (rejects empty, `.`/`..`, leading-dot, `/`,
  `\`, whitespace, control chars) at the **lowest ref-write boundary** — inside
  `refs::write_branch_tip` **and** `refs::read_branch_tip` — so one choke point guards
  **every** writer (CLI, wire `UpdateRef`, undo, ws), mirroring how `write_remote_tip`
  already self-guards. Requires exposing/moving `validate_branch_name` (currently
  `pub(crate)` in `repo.rs`) into or reachable from the refs layer; `Repo::branch`'s
  call becomes redundant belt-and-suspenders (drop or keep — build-time call).
- Use the **strict policy** rule, not the lighter `is_unsafe_ref_component` safety
  guard, because remote `UpdateRef` also writes the space-delimited **oplog**, which the
  safety guard (it allows whitespace/control and `/`) would not protect.
- **Also (adjacent gap found while resolving):** `refs::write_remote_tip`'s
  `is_unsafe_ref_component` allows whitespace/control, so a hostile **git remote's**
  branch name (via `fetch`) can carry one into a remote-tracking ref (same oplog class).
  Upgrade that guard to reject whitespace/control too — both ref-write paths hardened,
  no asymmetric gap.

## Decision 3 — DoS caps on untrusted lengths

An untrusted peer can drive large allocations (audit High). **Disposition: fix-now.**

- **Anchor:** a single `MAX_OBJECT_SIZE` constant (**~256 MiB** — bounds the 4 GiB
  worst case while fitting real blobs) representing the largest single object accepted.
  A wire frame and a pack record each carry at most one object, so this one number caps:
  1. `wire::read_frame_inner` — reject `len > MAX_OBJECT_SIZE` before `vec![0u8; len]`.
  2. `core::pack::parse_pack_reader` — reject a record `compressed_len > MAX_OBJECT_SIZE`
     before allocating, **and** bound the `zstd::decode_all` output to `MAX_OBJECT_SIZE`
     (decompression-bomb guard — a small compressed payload must not decode unbounded).
- **Chunk frames** stay bounded by the existing `CHUNK_SIZE` (1 MiB) on the P25 path;
  the frame cap is the backstop.
- **Collection counts (mechanical):** four object-decode sites allocate
  `Vec::with_capacity(n)` from a raw `r.u32()?` before consuming bytes — **tree entries,
  snapshot parents, secrets, signature wrapped-keys** (`core::object`). Switch each to
  the existing `Reader::count()` guard (rejects a count exceeding remaining bytes), the
  same guard the P16 protection decode already uses.
- Constants for the MVP; a `--max-object-size` operator knob is a deferred follow-on.
- **Build-time check:** whether the local store's object-acceptance (`put_object`/
  `commit`) should enforce the same `MAX_OBJECT_SIZE` for consistency (else a locally-
  committed >cap blob could never transfer); whether to tightly cap `ST_PACK_CHUNK`
  frames at `CHUNK_SIZE`.

## Decision 4 — protected-path equality leak

`encrypt_path`'s convergent encryption (DEK/nonce = `BLAKE3(plaintext)`) is equality-
confirmable — a deliberate, ADR-0014-documented tradeoff enabling dedup, not a bug.
The gap is that the `sc protect` CLI surface doesn't warn. **Disposition: fix-now
(nudge + docs) / defer (randomized mode).**

- **Pattern-aware nudge:** when `sc protect <prefix>` would encrypt a path whose
  basename looks like a low-entropy secret — `.env` / `.env.*` / `*.pem` / `*.key` /
  `id_*` / `*credentials*` / `*.p12` and similar (a heuristic in the spirit of the P5
  scanner) — print a targeted stderr steer: prefer `sc secret` (Phase 2 named secrets)
  for API keys / .env / license files. Warning-only (proceeds); quiet on ordinary
  source. Strengthen the `sc protect` help + an ADR-0014/CLAUDE.md pointer.
- **Deferred:** an opt-in **randomized protected mode** (non-convergent DEK/nonce) for
  high-sensitivity paths — trades dedup for equality-hiding. Its own effort.
- **Build-time check:** reuse/extend the P5 scanner's patterns for the heuristic set.

## Decision 5 — secret env-var confidentiality

`sc run` injects decrypted secrets as child env vars — the Phase-2 "authorized
execution context" design; the child-env exposure (same-user processes, crash dumps,
shell wrappers) is fundamental and kernel-copied. **Disposition: fix-now (docs +
parent zeroize) / defer (fd injection).**

- **Docs:** tighten the threat-model wording (ADR-0008/0009, CLAUDE.md, `sc run` help)
  to **"authorized LOCAL PROCESS context, NOT strong isolation."**
- **Cheap parent-side hardening:** wrap the intermediate decrypted `plaintext` buffer
  (`secrets.rs::secret_env`) in `crypto::Zeroizing` (re-exported since P15) so the
  **parent** process's copy is zeroed on drop, shrinking the parent-memory/crash-dump
  window. Does not fix the child-env exposure (fundamental, stays documented).
  Build-time check: whether `scl_crypto::open` already returns a `Zeroizing` type.
- **Deferred:** file-descriptor / stdin secret injection for commands that support it —
  a real alternative to env vars, its own effort.

## Build sequencing (for the phase)

**Fix-now, independent, small — can land together:**
- Decision 2 (ref-name validation) — one validator at the ref boundary + the
  remote-tracking guard upgrade.
- Decision 3 (DoS caps) — one constant, three size caps, one zstd bound, four
  `count()` swaps.
- Decision 4 (protect nudge + docs) and Decision 5 (env-var docs + parent zeroize).

**Design-then-fix, larger — its own build unit:**
- Decision 1 (sc+http access control) — the `--read-only` flag + fail-closed bind
  posture are small; the bearer-token auth (opening parse extension, `.sc/serve-tokens.toml`,
  scope gate, `sc serve token` CLI) is the substantive piece.

## Out of scope / deferred follow-ons

- Opt-in **randomized protected mode** (Decision 4).
- File-descriptor / stdin **secret injection** (Decision 5).
- A `--max-object-size` operator **config knob** (Decision 3).
- **mTLS / TLS** in-process — remains the fronting-reverse-proxy's job (Decision 1).
- The three P26 `sc serve --http` hardening items already in ROADMAP Deferred
  (connection pool/backpressure, idle-transfer watchdog, accept-loop backoff) — related
  but pre-existing; not part of this security spec.
