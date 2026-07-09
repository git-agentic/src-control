# P29 — sc+http access control: design

**Date:** 2026-07-09
**Status:** Decision-complete (ready for the P29 implementation plan)
**ADR:** 0040 (Proposed)
**Builds on:** ADR-0036 (P26 sc-native HTTP transport), ADR-0002 (BLAKE3), ADR-0022
(ssh-native transport — the auth-delegation precedent), the security-hardening spec
`2026-07-09-security-hardening-design.md` (Decision 1, decided via the wayfinder map).

## Problem

P26 shipped `sc serve --http` as an **unauthenticated, unrestricted** server: any client
that can reach the TCP port can read *and write* the repo, and a non-loopback bind is
accepted silently. That is the audit's remaining High (the sc+http server). P28 (the
security hardening sweep) closed the concrete ref-traversal and DoS bugs; P29 closes the
access-control gap and finishes the security horizon.

The design was decided at the decision level via the wayfinder map (security-hardening spec,
Decision 1). This spec resolves the build-level specifics into a buildable form; it does not
re-litigate the decided choices (read-only mode, fail-closed bind, dep-free bearer tokens,
`.sc/serve-tokens.toml`, `SC_HTTP_TOKEN`, the `sc serve token` CLI).

## The access-control matrix (the security backbone)

Three gates compose. This is the authoritative behavior.

### ① Bind gate — fail-closed (`serve_http`, before binding)

- **Loopback** host (`127.0.0.0/8`, `::1`, or the literal `localhost`) → always allowed.
- **Non-loopback** host (`0.0.0.0`, a LAN IP, `::`, any other) → **refused** unless at least
  one justification holds: `--read-only`, `--allow-public`, or ≥1 token in
  `.sc/serve-tokens.toml`. Otherwise a clear error naming the three ways to proceed.

### ② Auth gate — per connection (after reading the opening, before the `200`)

- **Tokens configured** (≥1 entry in `serve-tokens.toml`) → a valid `Authorization: Bearer`
  is **required on every connection, loopback included** — no bypass. Missing/invalid →
  `401`, close. Valid → adopt that token's scope.
- **No tokens configured** → no auth; the connection proceeds (exactly today's behavior, and
  only reachable because the bind gate allowed the listener to exist at all).

### ③ Read-only gate — per connection (the bool handed to the wire dispatch)

- `read_only = (--read-only) OR (matched token.scope == "ro")`.
- `--read-only` is a server-wide **floor**: an `rw` token cannot elevate above it (rw token +
  `--read-only` server → still read-only). An `rw` token on a plain server permits mutations.
  No tokens + no `--read-only` → full access.

**Sharp edge, sanctioned by design:** `--allow-public` alone (no tokens, no `--read-only`) is
a fully open, unauthenticated public read-*write* server. It is an explicit operator override
Decision 1 permits — the operator typed the words and owns the risk.

## Build-level decisions

### A. Token format

`sct-<64 hex>` = 32 bytes of OS randomness (256-bit), `sct-` prefix for human recognition
(matching `scl-id-`/`scl-sig-`). `serve-tokens.toml` stores `hash = hex(BLAKE3(raw bearer
string))` — the exact string the client sends after `Bearer `, so verification is a single
`BLAKE3(presented) == stored` with no decode step. High entropy means a plain hash suffices
(no KDF/salt — Decision 1). The raw token is printed **once** to stdout on `add` and never
persisted.

### B. Opening parse extension

`read_client_opening` returns `ClientOpening { target: String, bearer: Option<String> }`
instead of a bare `String`. It parses only `Authorization: Bearer <token>` (case-insensitive
header name; value is everything after `Bearer `), ignoring all other headers — no general
header map (YAGNI). The single caller (`handle_http_connection`) updates.

### C. Read-only enforcement seam

Add `wire::serve_with_policy(root, r, w, read_only: bool)`; keep `wire::serve` as a thin
wrapper delegating with `read_only = false`, so the ~10 existing callers (stdio transport,
sync, tests) are untouched and only the http server calls the policy variant. When
`read_only`, the three mutating verbs — `PutObject`, `PutPack`, `UpdateRef` — are rejected
**before any store write** with a new wire error code `EC_READONLY` → `Error::ReadOnly`,
surfaced client-side as a clear "server is read-only" message. Read verbs (`ListRefs`,
`HeadBranch`, `HasObject`, `GetObject`, `GetPack`) are always allowed; `sc backfill` is a
client `GetPack`, so it works against a read-only server.

### D. Constant-time compare

`BLAKE3(presented)` is compared against each stored hash with a std fold-XOR-accumulate
equality (no early return), iterating all tokens without short-circuiting on match. No new
dependency (Decision 1's "std-implementable"). On match, adopt that token's scope for the
connection's read-only gate.

### E. CLI grammar

- `sc serve --http <addr> <path> [--read-only] [--allow-public]` (extends the existing
  command; `--stdio` unchanged — auth there is ssh's job).
- `sc serve token add --label <name> --scope <ro|rw>` → generate a token, print the raw value
  once, store `{label, hash, scope}` in the cwd repo's `.sc/serve-tokens.toml`; error if the
  label already exists.
- `sc serve token remove <label>` (error if absent).
- `sc serve token list [--json]` — labels + scopes, never the token value.
- Rotation = add-new + remove-old (no expiry metadata). `serve-tokens.toml`:
  `[[token]] label = "…", hash = "…", scope = "ro|rw"`.

### F. Client

`HttpTransport::connect` reads `SC_HTTP_TOKEN`; if set, it sends `Authorization: Bearer
<token>` in the opening (the raw token stays out of argv/history — the `SC_SSH`/`SC_GIT`
pattern). A `401` maps to a distinct, clear error ("authentication required or token
rejected; set `SC_HTTP_TOKEN`") — never confused with `404`/`NotARepo`. `write_status` gains
`401 Unauthorized` (alongside 200/404/400).

## Data flow

```
client                                    server (sc serve --http)
------                                    ------------------------
TcpStream::connect                        accept → thread
write opening (+ Bearer if SC_HTTP_TOKEN) → read_client_opening → ClientOpening{target,bearer}
                                          ① bind gate already passed at bind time
                                          ② auth gate: tokens configured?
                                               yes → verify bearer (const-time BLAKE3)
                                                     miss/absent → 401, close
                                                     match → scope → read_only bool
                                               no  → proceed (read_only from --read-only)
read status: 200 proceed / 401 auth err   ← write_status(200)   (or 401 and close)
                                          ③ serve_with_policy(root, r, w, read_only)
WireClient handshake …                        mutating verb while read_only → EC_READONLY
```

## Error / status surface

- **HTTP openings (pre-wire):** `200` proceed, `400` malformed opening, `404` `.sc` absent,
  `401` missing/invalid token. `401` is written before any wire byte, mirroring the existing
  400/404 pre-handshake pattern.
- **Wire (post-200):** a mutating verb on a read-only connection → `EC_READONLY` →
  `Error::ReadOnly` ("server is read-only") at the client. All other wire semantics unchanged.

## Testing

- Unit: `ClientOpening` parse (bearer present / absent / case-insensitive header / malformed);
  loopback classification (`127.0.0.1`, `::1`, `localhost` vs `0.0.0.0`, a LAN IP, `::`);
  constant-time compare correctness (match / no-match / among several); token file
  round-trip; `read_only` bool derivation for every matrix cell.
- Integration (real loopback TCP, as P26): tokens-configured server → no-token connect `401`;
  ro-token clone succeeds but push → `EC_READONLY`; rw-token push succeeds; non-loopback bind
  refused without justification; loopback-no-tokens still works (regression).
- Every P26 sc+http test stays green (the no-auth, no-read-only path is the default and
  unchanged).

## Demo

`demo/run_http_auth_demo.sh` (real loopback TCP, no shim): start a token-configured
`sc serve --http 127.0.0.1:<port> .`; prove (1) a no-token clone gets `401`; (2) an ro-token
clone succeeds but an ro-token push is rejected read-only; (3) an rw-token push lands and a
later clone sees it; (4) `sc serve --http 0.0.0.0:<port> .` is refused without a justification
and accepted with one. Run twice, assert zero `.sc/tmp` residue.

## Scope & boundaries (restated for the ADR)

- Plaintext only, **no TLS** — `sc+https://` is deferred to a TLS-dependency phase or a
  fronting reverse proxy (TLS stays the proxy's job, per the P25/P26 dep-free grain).
- Bearer tokens only: no expiry/rotation metadata beyond add/remove; rotation is add-new +
  remove-old.
- **Loopback-with-no-tokens stays unauthenticated by design** (local dev ergonomics); auth is
  opt-in via configuring tokens, which then binds every connection.
- `--stdio`/ssh transport is unchanged — auth there is ssh's (ADR-0022).
- The three P26 `sc serve --http` hardening items (connection pool/backpressure, idle-transfer
  watchdog, accept-loop backoff) remain deferred — orthogonal operational hardening, not
  access control.

## Phase bookkeeping

P29 closes the security horizon (P28 sweep + P29 access control). ADR-0040 Proposed → Accepted
at build completion. ROADMAP Active → P29; the next horizon (agent/workspace depth, anchored
by P30 session transcripts, ADR-0038) follows.
