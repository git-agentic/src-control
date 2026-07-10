# ADR-0042: In-binary TLS — `sc+https://` via rustls

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 32
- **Builds on:** ADR-0036 (P26 sc-native HTTP transport — reserved the
  `sc+https://` scheme and named "no TLS" as an accepted consequence),
  ADR-0040 (P29 access control — the bearer-token/bind-gate machinery this
  phase extends), ADR-0041 (P31 listener resource limits — the
  `--max-connections` accept-thread-never-blocks property this phase must not
  violate)
- **Research:** `docs/research/tls-options-sc-http.md` (ticket #25 — measured
  dependency counts, provider survey, reverse-proxy both-legs correction).
  Decided at the decision level via tickets #26 (transport choice) and #35
  (provisioning + TOFU UX), the phase spec at #39.

## Context

The 2026-07-09 security audit's High #1 (ticket #24's map) is that
`sc serve --http` is plaintext: a bearer token (ADR-0040) and all repository
traffic cross the wire in the clear. ADR-0036 named this as an accepted
consequence and reserved the `sc+https://` scheme for "when TLS lands";
`docs/THREAT-MODEL.md` told operators to front a public deployment with a TLS
reverse proxy. The #25 research pass found that guidance incomplete: a
server-side proxy terminates TLS toward clients that speak TLS, but `sc`'s own
client spoke only plaintext TCP, so the proxy alone protected nothing
end-to-end — the *client* leg needed wrapping too (client-mode stunnel,
`ssh -L`), a burden the existing docs never stated.

## Decision — why in-binary TLS is load-bearing here

Two comparable Rust servers, Vaultwarden and Garage, both decline to ship
in-binary TLS and instead punt to a reverse proxy
(`docs/research/tls-options-sc-http.md` §"Maturity / prior art"). That
precedent does not transfer to `sc`. Vaultwarden and Garage are server-only:
their proxy story covers the one leg that exists. `sc` is a CLI whose
**client** half must reach servers its operator does not control — a
teammate's laptop, a CI runner hitting a third-party host, a contributor
cloning from an unfamiliar remote. No reverse proxy can be placed in front of
a server the `sc` operator doesn't administer. This is the case a
"front it with nginx" answer structurally cannot cover, and it is why this
phase ships TLS in the binary rather than only writing the (still necessary)
both-legs proxy documentation.

## Provider

rustls **0.23.41**, **ring** crypto provider (`default-features = false`,
`features = ["ring", "std", "tls12", "logging"]`): ~14 new crates measured
against this repo's `Cargo.lock`, requiring a C compiler only (ring is
mostly assembly/C, no cmake). The rustls-default provider, **aws-lc-rs**, was
rejected as the primary choice — 18 new crates plus a cmake + C-compiler build
requirement — but is recorded here as the **swap-in fallback** if ring's
build story ever proves insufficient on a target platform, since both
providers implement the same `rustls::crypto::CryptoProvider` trait and the
swap touches no call site above it. Pure-Rust providers (`graviola`,
`rustls-rustcrypto`) were rejected as immature: `rustls-rustcrypto`
self-describes as "experimental," covering an estimated 70% of usage;
`graviola`'s RSA support is limited to five fixed key sizes.

## Quarantine

`crates/tlsio` (`scl-tlsio`) is the only crate linking `rustls`, `rcgen`,
`ring`, and `rustls-pki-types` — the same discipline as `gix`→`gitio` and
RustCrypto→`crypto`. It is a workspace dependency **leaf**: unlike its
sibling crates (`vfs`, `gitio`, `crypto`), it depends on no other workspace
crate, not even `core`. The dependency rule gains one edge:
`cli → repo → {vfs, gitio, crypto, tlsio}`, with `{vfs, gitio, crypto} → core`
unchanged. `repo` is the sole consumer. SHA-256 (used for the SPKI
fingerprint) goes through `ring::digest`, **not** the RustCrypto stack in
`crates/crypto` — that quarantine holds; `tlsio` never links `sha2` or any
other RustCrypto crate.

## Trust model

Accept-new TOFU, the SSH `known_hosts` shape, stated plainly: **the first
connection to a host is unverified by construction.** The pin is
`SHA-256(full SPKI DER TLV)` — the standard "pin the public key, not the
cert" approach, which survives a same-key certificate renewal and is
independently verifiable with `openssl x509 -pubkey | openssl pkey -pubin |
openssl dgst -sha256`. Pinning is **pin-only in v1**: certificate names and
validity periods are deliberately ignored (the pin itself carries the trust
decision), but the TLS **handshake signature is still verified** — a
pinned-certificate MITM replaying a captured cert without the matching
private key is rejected at the handshake, not just at pin comparison. A pin
mismatch **always hard-fails** — it never prompts or offers to proceed, the
same discipline SSH's `StrictHostKeyChecking` enforces for a changed key.

Storage and knobs:

- `~/.config/sc/known_hosts` (`$XDG_CONFIG_HOME/sc/known_hosts` if set,
  falling back to `$HOME/.config/sc/known_hosts`; `SC_HTTPS_KNOWN_HOSTS`
  overrides the path outright), one `host:port sha256:<hex>` line per pin.
- `SC_HTTPS_FINGERPRINT=sha256:<hex>` pre-pins a connection (e.g. for CI)
  without ever writing to the known_hosts file — an explicit, non-persisted
  override.
- `SC_HTTPS_STRICT=1` refuses to connect to any host with no existing pin,
  closing the accept-new window for operators who want SSH's
  `StrictHostKeyChecking=yes` equivalent (`=1` enables it; any non-empty
  value other than `0` is also treated as enabled — it fails closed on a
  typo like `=true` rather than silently falling back to accept-new).
- The server prints its SPKI fingerprint on the `sc serve --tls` startup
  banner and via `sc serve fingerprint [<path>]` (which mints the identity if
  missing), so an operator can distribute the pin out-of-band before a
  client's first connection.

## Server lifecycle

`sc serve --http <addr> <path> --tls [--tls-cert <pem> --tls-key <pem>]`.
Without PEM flags, the server auto-mints a self-signed identity into
`.sc/serve-tls/` (`cert.pem` + `key.pem`, key file `0600` — the key file IS
the server's identity, so its permissions matter the same way an SSH host key
does), regenerating only when the material is missing, `not_after` set to
2126 (a century out — self-signed + TOFU pinning makes expiry-driven rotation
meaningless without a CA, so the cert's own validity window is not the trust
mechanism; the pin is). `--tls` is refused together with `--stdio` (ssh
already provides that channel's confidentiality end to end — layering TLS
under it protects nothing new). ACME was rejected outright: `rustls-acme`
pulls in `async-io` and an async HTTP + `serde_json` stack, wrong-shaped for
this project's blocking, minimal-dependency design; an operator who wants a
CA-issued cert runs certbot or a proxy and supplies `--tls-cert`/`--tls-key`.

## Gate change (breaking)

Per decide ticket #26/#35 and the phase spec: a non-loopback bind is allowed
iff `--read-only` OR `--allow-public` OR (`--tls` AND ≥1 serve token
configured). **Tokens alone no longer justify a plaintext public bind** — the
P29 gate (`--read-only | --allow-public | ≥1 token`) is narrowed so a
plaintext token-only deployment, which used to be accepted, is now refused
with a message naming `--tls` as the fix. This is a deliberate breaking
change to `bind_is_allowed`'s contract, justified by the same reasoning as
the rest of this ADR: a bearer token protecting nothing but a plaintext
channel was always a weaker guarantee than the gate's wording implied.

## Accepted consequences

1. **Under TLS, the `--max-connections` busy-shed closes silently instead of
   writing a readable `503`.** Writing a `503 Service Unavailable` requires a
   TLS handshake, and performing that handshake on the accept thread would let
   one slow or hostile client stall every subsequent `accept()` — exactly the
   property ADR-0041 exists to protect (accepts must never block). Plaintext
   connections keep the readable `503`; TLS connections at the connection cap
   simply see the socket close. This is a real behavior gap from the phase
   spec's first draft (which assumed the busy status could ride the TLS
   channel) — deliberately kept as a silent close rather than adding
   handshake work to the accept path, and recorded in the amended spec
   (`docs/superpowers/specs/2026-07-10-p32-tls-sc-https-design.md` §3).
2. **A new API-break tracking burden.** This is the project's first TLS
   dependency; rustls's 0.23→0.24 boundary is a real API break to track on
   the next upgrade, unlike the additive minor-version bumps most of this
   project's dependencies see.
3. **CA-path validation is deferred.** v1 ships pin-only trust; validating a
   presented cert against a system/operator-supplied CA bundle as an
   *additional* trust path (for PEM-provisioned deployments that already have
   a real CA-issued cert) is additive follow-on work, not a v1 requirement.
4. **The plaintext-gate break is pre-1.0 and narrow.** The project is not yet
   at a stability guarantee, and the affected case — a plaintext non-loopback
   bind justified by tokens alone — is exactly the case this phase's own
   audit finding targets; narrowing it is the fix, not incidental breakage.

## Consequences

- `PROTOCOL_VERSION` stays 3: TLS wraps below the opening codec, which is
  unchanged (`wire.rs`, `read_bounded_opening`, `serve_tokens.rs` all
  untouched).
- `sc+https://` joins `sc+http://` and `ssh://` as a third confidential-or-not
  transport choice; `ssh://` (ADR-0022) was already fully confidential and is
  now explicitly promoted as such in `docs/THREAT-MODEL.md`.
- The both-legs reverse-proxy documentation gap the #25 research pass found
  is closed by this ADR's existence — but is now also a fallback rather than
  the only confidential option, since `sc+https://` and `ssh://` both exist.
- Proven by `demo/run_tls_demo.sh`: a TLS round trip carrying a signed chunked
  blob, the TOFU pin/mismatch/strict/pre-pin lifecycle, and the tightened
  plaintext gate refusing a token-only public bind — run twice, zero residue.

## Rejected alternatives

- **aws-lc-rs as the primary provider.** Rejected for its heavier build
  requirement (cmake + C compiler vs. ring's C-compiler-only); recorded above
  as the fallback, not eliminated from consideration.
- **A pure-Rust provider (`graviola`, `rustls-rustcrypto`).** Rejected as
  immature for a security-load-bearing path — see Provider above.
- **The `rustls-pin` crate for fingerprint pinning.** Targets rustls 0.19,
  five majors stale; a hand-written ~100-line `ServerCertVerifier` was
  written instead, following the pattern in rustls's own test suite.
- **ACME in-binary (`rustls-acme`).** Rejected — async-only dependency
  stack, wrong fit for this project's blocking I/O design.
- **Sending a readable `503` under TLS at the connection cap.** Rejected —
  would require an accept-thread TLS handshake, violating ADR-0041's
  accepts-never-block property. See Accepted consequences #1.
- **Noise protocol (`sc+noise://` via `snow`) instead of TLS.** Considered in
  the research doc (Option C3) as the smallest marginal dependency footprint,
  but rejected for this decision: no operator/proxy/certificate ecosystem
  (no path for an operator who wants to terminate at nginx or use a
  CA-issued cert), an explicitly unaudited crate, and a bigger architectural
  bet (sc's network identity becoming scl-id keys rather than x509) than this
  ticket scoped.
