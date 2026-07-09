# ADR-0040: sc+http access control

- **Status:** Accepted
- **Date:** 2026-07-09
- **Phase:** 29
- **Builds on:** ADR-0036 (P26 sc-native HTTP transport), ADR-0002 (BLAKE3),
  ADR-0022 (ssh transport — the auth-delegation precedent), ADR-0039 (P28 security
  hardening sweep — the first half of this horizon)
- **Spec:** `docs/superpowers/specs/2026-07-09-p29-sc-http-access-control-design.md`
  (decision-complete). Decided at the decision level in
  `2026-07-09-security-hardening-design.md` (Decision 1) via the wayfinder map.

## Context

P26 shipped `sc serve --http` unauthenticated and unrestricted: any client reaching the
port reads *and writes* the repo, and a non-loopback bind is accepted silently. That is
the security audit's remaining High. P28 closed the concrete ref-traversal and DoS bugs;
this ADR closes the access-control gap and finishes the security horizon. The design is
the wayfinder-decided Decision 1; this ADR firms it into a built form.

## Decision

Access control for `sc serve --http` composes three gates, dep-free (BLAKE3 is already a
dependency; constant-time compare is std-implementable — no TLS, no new crate):

1. **Fail-closed bind.** A non-loopback bind is refused unless justified by `--read-only`,
   `--allow-public`, or ≥1 configured token; loopback always binds.
2. **Bearer-token auth at the HTTP opening.** When `.sc/serve-tokens.toml` holds ≥1 token,
   a valid `Authorization: Bearer <token>` is required on **every** connection (loopback
   included). The check sits at the opening — `read_client_opening` returns
   `ClientOpening { target, bearer }`; `handle_http_connection` constant-time-compares
   `BLAKE3(presented)` against stored hashes and writes `401` before the `200`/wire handoff
   on a miss. Tokens are `sct-<hex>` (256-bit random), stored as
   `{label, hash = BLAKE3(raw), scope = ro|rw}`; the raw token is printed once and never
   persisted. The client presents it via `SC_HTTP_TOKEN` (the `SC_SSH`/`SC_GIT` pattern).
3. **Read-only enforcement.** `--read-only`, or a matched `ro`-scope token, sets a
   per-connection `read_only` flag threaded into `wire::serve_with_policy`, which rejects
   the three mutating verbs (`PutObject`/`PutPack`/`UpdateRef`) **before any store write**
   with a typed `EC_READONLY` wire error. `--read-only` is a floor an `rw` token cannot
   elevate. Reads (incl. `sc backfill`'s `GetPack`) always pass.

The wire protocol is **unchanged** except for the new `EC_READONLY` error code — so the
ssh path (already ssh-authenticated) is untouched, and a reverse proxy can inject/validate
the `Authorization` header. `wire::serve` stays a thin wrapper delegating to
`serve_with_policy` with `read_only = false`, so no existing caller changes.

## Consequences

- The audit's unauthenticated-server High is closed; the security horizon (P28 + P29) is
  complete. No new dependency; no TLS.
- Authentication is **opt-in**: configuring a token turns it on and then binds every
  connection (loopback included). Loopback-with-no-tokens stays unauthenticated by design
  for local-dev ergonomics — a deliberate, documented default, not a gap.
- Enabling tokens satisfies the fail-closed public-bind gate — a token-required server is
  no longer "unauthenticated," so it may bind publicly.
- `--allow-public` alone remains a sanctioned foot-gun: a fully open public read-write
  server, entered explicitly by the operator.
- `sc serve token add/remove/list` join `sc keygen`/`sc secret` as local-config commands;
  rotation is add-new + remove-old (no expiry metadata in the MVP).
- The build closed one review-found fail-open: a non-loopback bind justified only by
  configured tokens now fails closed (`401` on every connection, not an open server) if its
  last token is removed while the server is still running.

## Alternatives considered

- **mTLS instead of bearer tokens.** Would be the project's first TLS dependency, against
  the P25/P26 dep-free grain; TLS stays the fronting-proxy's job. Rejected.
- **Auth inside the wire protocol (a new HELLO field).** Would change the wire format and
  entangle the ssh path (already authenticated). Rejected — the HTTP opening is the right,
  transport-scoped seam, and keeping the wire unchanged lets a reverse proxy handle the
  header.
- **Per-path/per-ref ACLs.** Beyond the MVP; scope is all-or-nothing per connection
  (`ro`/`rw`), which covers the read-mirror and trusted-writer cases the audit named.
  Deferred.
- **Always-on auth (no unauthenticated loopback).** Rejected for local-dev ergonomics; the
  bind gate already contains the exposure to loopback when no tokens exist.

## Threat model honesty

- **Defends:** unauthorized reads/writes over `sc+http://` (token-gated); accidental public
  exposure (fail-closed bind); unaudited mutation (read-only scope). A `ro` token is a safe
  read-mirror credential; an `rw` token is a trusted-writer credential.
- **Does NOT defend:** network eavesdropping or MITM — there is **no TLS**; a bearer token
  crosses the wire in plaintext, so a public deployment must front with a TLS reverse proxy.
  Nor does it defend against a leaked token (bearer, reusable until removed) or a malicious
  holder of a valid token. Not HTTP-proxy/CDN-safe (the raw post-opening protocol), as P26.
- **Minor pre-auth information leak:** the `.sc`-missing `404` is written before the auth
  gate, so an unauthenticated client can distinguish "a repo is served here" (`401`) from
  "no repo here" (`404`) — repo *presence* is observable pre-auth, though no content is.
  Ordering the `404` after the auth check would close it; deferred (ROADMAP).
