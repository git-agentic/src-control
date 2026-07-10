# Research: keeping sc+http bearer tokens and repository traffic confidential

- **Ticket:** [#25 — wayfinder: sc+http confidentiality options](https://github.com/git-agentic/src-control/issues/25)
- **Question:** What are the viable options for keeping sc+http bearer tokens and
  repository traffic confidential, and what does each cost?
- **Date:** 2026-07-10. Research for decision ticket #26 — this document frames
  options and costs; it does not decide.
- **Method:** primary sources only (official docs, crate manifests/docs.rs, specs,
  the projects' own repos), cited inline; dependency counts were **measured** with
  `cargo tree` on scratch projects against today's crates.io (not taken from
  secondary write-ups) and diffed against this repo's `Cargo.lock`.

## 0. Status quo, and the one seam every option plugs into

Today (`crates/repo/src/http_transport.rs`, ADR-0036, ADR-0040):

- `sc+http://` runs over a plain `TcpStream`: a hand-rolled HTTP/1.1 opening
  (request line + headers, read via `read_bounded_opening`, 8 KiB cap), then the
  raw socket hands off to the framed binary wire protocol
  (`crates/repo/src/wire.rs`, `PROTOCOL_VERSION = 3`).
- Auth (P29) is an `Authorization: Bearer sct-<hex>` header; the server stores
  `BLAKE3(raw)` in `.sc/serve-tokens.toml` and constant-time-compares
  (`crates/repo/src/serve_tokens.rs`). The raw token is printed once, never
  persisted.
- **No TLS anywhere.** `docs/THREAT-MODEL.md` states the boundary: the token
  crosses the wire in the clear; "a public deployment MUST be fronted by a TLS
  reverse proxy; `sc+https://` is deferred." ADR-0036 reserved the `sc+https://`
  scheme for "when TLS lands"; `ROADMAP.md` defers a first-party TLS dependency
  "against the P25/P26 dep-free grain."

**The load-bearing implementation fact common to every option:** both ends of the
wire protocol are fully generic over `std::io::Read + Write` —
`WireClient<R: Read, W: Write>` (`crates/repo/src/stdio_transport.rs:19`) and
`serve_with_policy(root, r: &mut impl Read, w: &mut impl Write, read_only)`
(`crates/repo/src/wire.rs:604`). The concrete `TcpStream` appears in exactly two
functions: `HttpTransport::connect_with_token` (client) and
`handle_http_connection` (server), both in `http_transport.rs`. Any encrypting
stream wrapper that implements `Read + Write` slots in at that seam with no
change to the wire protocol itself.

**MSRV is a non-issue for every candidate:** the workspace pins
`rust-version = "1.96.1"` (root `Cargo.toml`), far above rustls's MSRV of 1.71
([rustls Cargo.toml, v0.23.41](https://raw.githubusercontent.com/rustls/rustls/v/0.23.41/rustls/Cargo.toml)).

**One correction to the framing worth stating up front:** the current
"front with a TLS reverse proxy" guidance is *incomplete as written*. A
server-side proxy terminates TLS **toward clients that speak TLS** — but today's
`sc+http://` client speaks only plaintext TCP. A server-side proxy alone
therefore encrypts nothing end-to-end: the *client* leg must also be wrapped
(client-mode stunnel, an `ssh -L` tunnel, a VPN) until sc itself can speak TLS.
stunnel's own docs confirm the symmetric client mode exists for exactly this
(`client = yes`, [stunnel config guide](https://www.stunnel.org/config_unix.html)),
but it doubles the operator burden and the current docs don't say so. Any
resolution of #26 that keeps "reverse proxy" as the answer must document both
legs — or note that sc already ships a fully confidential transport, `ssh://`
(P12/ADR-0022), for operators who have ssh reach.

---

## Option A — In-binary TLS via rustls (`sc+https://`)

### What it protects

Token confidentiality, traffic confidentiality, active-MITM resistance (given
either CA validation or fingerprint pinning), replay and session-hijack
resistance — the full set. The bearer token stays as the *authorization*
mechanism; TLS provides the confidential channel it rides in.

### Dependency cost (measured 2026-07-10, `cargo tree`, scratch project)

Current stable is rustls **0.23.41** (2026-06-22,
[crates.io](https://crates.io/api/v1/crates/rustls)); mandatory deps are only
`once_cell`, `rustls-pki-types`, `subtle`, `rustls-webpki`, `zeroize`
([docs.rs metadata](https://docs.rs/crate/rustls/latest)). The variable cost is
the **crypto provider**:

| Stack (rustls + rcgen) | Unique crates (scratch) | New vs this repo's `Cargo.lock` | Native toolchain needed |
|---|---|---|---|
| default provider = **aws-lc-rs** | 31 | 18 (`aws-lc-rs aws-lc-sys base64 cmake deranged fs_extra num-conv pem powerfmt rcgen ring rustls rustls-pki-types rustls-webpki time time-core untrusted yasna`) | **cmake + C compiler** (aws-lc-sys build deps: `cc`, `cmake`, `bindgen?`, `pkg-config` — [docs.rs](https://docs.rs/aws-lc-sys/latest/aws_lc_sys/)) |
| `features = ["ring", "std", "tls12", "logging"]`, `default-features = false` | 24 | **14** (`base64 deranged num-conv pem powerfmt rcgen ring rustls rustls-pki-types rustls-webpki time time-core untrusted yasna`) | C compiler only (ring is 46% assembly / 7% C per [its repo](https://github.com/briansmith/ring); no cmake) |
| pure-Rust providers | — | — | none, but see caveats |

- aws-lc-rs is the **default** provider since rustls 0.23 ("By default it uses
  aws-lc-rs" — [rustls docs](https://docs.rs/rustls/latest/rustls/); default
  features `aws_lc_rs, logging, prefer-post-quantum, std, tls12` per the
  [tagged Cargo.toml](https://raw.githubusercontent.com/rustls/rustls/v/0.23.41/rustls/Cargo.toml)).
- ring's own maintainer still frames it as "an experiment"
  ([ring README](https://github.com/briansmith/ring)) — it is the lighter build,
  not a stronger assurance story.
- Pure-Rust providers exist but are honestly not there yet:
  [graviola](https://github.com/ctz/graviola) (by rustls's lead maintainer;
  "no C compiler, assembler or other tooling needed", but RSA limited to
  sign/verify at five fixed key sizes) and
  [rustls-rustcrypto](https://github.com/RustCrypto/rustls-rustcrypto)
  (self-described **"experimental"**, "only a few selected TLS suites…
  expected to cover 70% of usage"). Either would keep the build pure-Rust at the
  cost of adopting an immature provider.
- **Not needed:** `webpki-roots` (Mozilla CA bundle) is not a rustls dependency
  ([docs.rs](https://docs.rs/crate/webpki-roots/latest)) and is unnecessary for
  self-signed/pinned deployments. `rustls-pemfile` is superseded — PEM parsing
  now lives in `rustls-pki-types` itself
  ([rustls-pemfile docs](https://docs.rs/crate/rustls-pemfile/latest)), which
  rustls already depends on, so **PEM loading costs zero extra crates**.
- `rcgen` 0.14.8 (self-signed cert generation) adds only `time`, `yasna`, `pem`,
  `base64` beyond the shared tree ([docs.rs](https://docs.rs/crate/rcgen/latest));
  its MSRV policy is rolling ("7-month-old Rust").

### Implementation surface

**No async runtime is needed.** `rustls::Stream`/`StreamOwned` implement
`io::Read + io::Write` over any blocking transport, including
`std::net::TcpStream` ([rustls docs](https://docs.rs/rustls/latest/rustls/);
the project's own tagged blocking examples:
[simpleserver.rs / simpleclient.rs @ v0.23.41](https://raw.githubusercontent.com/rustls/rustls/v/0.23.41/examples/src/bin/simpleserver.rs)).
Shape:

- Server: `ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)` →
  `ServerConnection::new(Arc<config>)` → `rustls::Stream::new(&mut conn, &mut tcp)`.
- Client: `ClientConfig::builder()…` → `ClientConnection::new(Arc<config>, server_name)` →
  `Stream::new(…)`. For SSH-known-hosts-style **fingerprint pinning**, implement
  the 4-method `rustls::client::danger::ServerCertVerifier` trait
  ([docs.rs](https://docs.rs/rustls/latest/rustls/client/danger/trait.ServerCertVerifier.html))
  and install it via `.dangerous().with_custom_certificate_verifier(v)` (pattern
  shown in [rustls's own test suite](https://docs.rs/crate/rustls/latest/source/tests/server_cert_verifier.rs)).
  The one pre-built pinning crate, `rustls-pin`, targets rustls 0.19 — five majors
  stale ([docs.rs](https://docs.rs/rustls-pin/latest/rustls_pin/struct.PinnedServerCertVerifier.html))
  — so the verifier is hand-written (~50–100 lines).

Files/functions that change (and only these — the seam holds):

- `http_transport.rs`: `HttpTransport::connect_with_token` wraps the `TcpStream`
  in a `StreamOwned<ClientConnection, TcpStream>` before `write_client_opening`;
  `handle_http_connection` wraps before `read_client_opening`. The opening codec,
  `read_bounded_opening`, `serve_tokens`, and all of `wire.rs` are **unchanged** —
  TLS sits *below* the opening.
- New `sc+https://` arm in `open_transport` (`stdio_transport.rs`) — the scheme
  ADR-0036 explicitly reserved. `sc+http://` remotes keep working unchanged.
- `sc serve --http` grows `--tls-cert/--tls-key` (user PEM) and/or an
  auto-`rcgen` self-signed path; client grows known-hosts-style fingerprint
  storage (e.g. `~/.config/sc/known_hosts` or `SC_HTTPS_FINGERPRINT`).
- **`PROTOCOL_VERSION` stays 3** — nothing in the wire protocol changes.
- Project discipline: this is the first TLS dependency (ADR required, per the
  RustCrypto/ed25519-dalek precedent). rustls is not a RustCrypto crate, so the
  existing `crates/crypto` quarantine doesn't cover it; the natural quarantine is
  the transport layer itself (`crates/repo`), recorded in the ADR.

### Operational cost

- **Self-signed + TOFU pinning:** zero operator burden (server mints a cert at
  first `serve`; client pins on first connect). Trust model = SSH known_hosts:
  first connection is vulnerable, later MITM is detected.
- **User-supplied PEM:** operators with real certs (certbot etc.) load them
  directly; zero extra crates (PEM parsing is in pki-types, above).
- **ACME in-binary: rejected.** `rustls-acme` has `async-io` as a *non-optional*
  dependency plus an async HTTP client + serde_json stack
  ([docs.rs](https://docs.rs/crate/rustls-acme/latest)) — inherently async,
  materially heavier, wrong fit for a blocking, minimal-dep server. Operators
  who want ACME run certbot or front with Caddy.

### Maturity / prior art

Cuts both ways. rustls is the de-facto Rust TLS implementation and a selectable
backend of rustup and gitoxide's client transports
([rustup #3400](https://github.com/rust-lang/rustup/issues/3400),
[gix features](https://docs.rs/gix/latest/gix/)) — but **cargo's own HTTPS
client is libcurl, not rustls** (`curl = { features = ["http2"] }` in
[cargo's Cargo.toml](https://github.com/rust-lang/cargo/blob/master/Cargo.toml)),
and the two self-hosted Rust servers checked both *decline* to ship production
in-binary TLS: Vaultwarden's docs steer operators to a reverse proxy over
Rocket's built-in TLS ([wiki: Enabling HTTPS](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-HTTPS)),
and Garage documents "the main reason to add a reverse proxy in front of Garage
is to provide TLS" ([Garage cookbook](https://garagehq.deuxfleurs.fr/documentation/cookbook/reverse-proxy/)).
Radicle, the closest VCS-native peer, uses **Noise (XK), not TLS**, for its peer
protocol ([protocol guide](https://radicle.dev/guides/protocol) — page fetch
returned 403; claim is from its search abstract, lower confidence). No
VCS-adjacent Rust *server* shipping in-binary rustls was found.

---

## Option B — Documented reverse-proxy-only (TCP-mode TLS termination)

### What it protects

Token + traffic confidentiality and MITM resistance **on the proxied leg only**,
and **only if the client leg is also wrapped** (see §0). The proxy→`sc serve`
loopback hop stays plaintext, so the bearer-token requirement must be kept
(defense on the loopback hop and the authorization function itself).

### What works — confirmed from official docs

The post-opening protocol is not HTTP, so an HTTP-mode reverse proxy will not
tunnel it (ADR-0036: "a strict proxy won't tunnel the post-opening raw
protocol"). Raw-TCP-mode TLS termination is required, and is supported by:

- **nginx** `stream {}` + `ngx_stream_ssl_module`: `listen <port> ssl` +
  `ssl_certificate`/`ssl_certificate_key` + `proxy_pass 127.0.0.1:<port>`
  ([ngx_stream_ssl_module](https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html)).
  Caveats: neither the `stream` block (`--with-stream`) nor its ssl module
  (`--with-stream_ssl_module`) is built by default
  ([ngx_stream_core_module](https://nginx.org/en/docs/stream/ngx_stream_core_module.html))
  — operators must check `nginx -V`. And `ssl_preread` is **routing only,
  explicitly without terminating TLS**
  ([ngx_stream_ssl_preread_module](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html))
  — the docs must warn against it. Bonus: stream-layer client-cert auth
  (`ssl_verify_client`) exists.
- **HAProxy** `mode tcp` + `bind :<port> ssl crt <pem>`
  ([TCP tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/protocol-support/tcp/),
  [client-cert auth](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/security/authentication/client-certificate-authentication/))
  — mature, first-class, with mTLS (`verify required ca-file …`) as a bonus.
- **stunnel**: TLS-wraps arbitrary TCP in *both* directions — server mode
  (`accept`/`connect`/`cert`) and client mode (`client = yes`)
  ([config guide](https://www.stunnel.org/config_unix.html)). Client mode is the
  piece that makes reverse-proxy-only a *complete* story today: a client-side
  stunnel gives the unmodified `sc+http://` client a TLS leg.
- **Caddy: not recommended as the primary documented path.** Layer-4 proxying is
  not in core Caddy; it requires the `caddy-l4` plugin, whose own README states
  it "is not an official repository of the Caddy Web Server organization" and
  "expect breaking changes" ([mholt/caddy-l4](https://github.com/mholt/caddy-l4);
  [caddyserver.com module page](https://caddyserver.com/docs/modules/layer4)
  confirms it's a non-bundled xcaddy build).

### What the operator doc must say (the actual deliverable of this option)

1. Terminate TLS in **raw-TCP / stream / layer-4 mode** (nginx `stream`,
   HAProxy `mode tcp`, stunnel) — never HTTP mode, never `Transfer-Encoding`.
2. Forward decrypted bytes to a **loopback-bound** `sc serve --http 127.0.0.1:…`.
3. **Keep the bearer token configured** — the loopback hop is plaintext and the
   token is still the authorization mechanism.
4. **Wrap the client leg too** (client-mode stunnel or `ssh -L`), because the sc
   client itself cannot speak TLS — or use the `ssh://` transport instead.
5. Certificates come from the operator (certbot etc.); none of
   nginx/HAProxy/stunnel automate ACME.

### Cost

Zero code, zero dependencies, zero `PROTOCOL_VERSION`/scheme impact. The cost is
entirely operational and falls on every operator, twice (server + client leg) —
and it leaves local/LAN "just try it" deployments plaintext by default, since
nobody stands up stunnel pairs for a quick share.

---

## Option C — Non-TLS options at the opening (no traffic confidentiality)

### C1. Challenge-response bearer auth (dep-free)

Server sends a random nonce; client returns `BLAKE3-keyed-hash(key, nonce)`
(BLAKE3 has a native 256-bit-key keyed/MAC mode —
[BLAKE3 README](https://github.com/BLAKE3-team/BLAKE3); HMAC per
[RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) is the classical equivalent).

- **Protects:** the reusable credential never crosses the wire (a passive sniffer
  gets only `(nonce, MAC)` pairs); replay is defeated per-connection by the fresh
  nonce. Offline brute-force of the response is only viable against low-entropy
  tokens — `sct-` tokens are 256-bit random (`serve_tokens::generate`), so this
  is moot.
- **Does NOT protect:** traffic stays plaintext; an active MITM can hijack the
  authenticated TCP session after the exchange (nothing binds subsequent bytes
  to the auth); repository content confidentiality is unchanged.
- **A non-obvious storage interaction (must be recorded if chosen):** the server
  stores `BLAKE3(raw)`, not the raw token, so the server *cannot* compute
  `keyed_hash(raw_token, nonce)`. The response must be keyed by something the
  server holds — i.e. `keyed_hash(BLAKE3(raw), nonce)` with the client hashing
  first. That makes the stored hash **password-equivalent** (pass-the-hash):
  today a stolen `serve-tokens.toml` cannot authenticate; under challenge-response
  it can. A trade of wire-theft resistance for at-rest-theft resistance.
- **Surface:** opening codec only — one extra round trip (e.g. server answers a
  token-less/CR-marked opening with `401` + a challenge header; client repeats
  the opening with the response header). `write_client_opening` /
  `read_client_opening` / `write_status` grow a header each;
  `HttpTransport::connect_with_token` and `handle_http_connection` gain the
  round trip. **Wire protocol untouched, `PROTOCOL_VERSION` stays 3, no new
  scheme.** Backward compatibility is a policy choice: the server can accept
  both plain `Bearer` and challenge-response during a transition, or a
  per-token/config flag can require CR.

### C2. Ed25519 signature auth (reuses existing identities)

Same shape as C1 but the client signs the server nonce with an existing
`scl-id` v2 Ed25519 identity (P22, `ed25519-dalek` already quarantined in
`crates/crypto`); the server keeps an authorized-key list (the
`recipients.toml [signers]` pattern already exists). This is SSH's publickey
method ([RFC 4252](https://www.rfc-editor.org/rfc/rfc4252)): server checks the
key is authorized, then verifies the signature over session-bound data.

- **Protects/doesn't:** as C1 (no traffic confidentiality, no MITM/hijack
  resistance), but with per-client identity and revocation instead of a shared
  bearer secret, and no pass-the-hash issue (server stores only public keys),
  and no offline-brute-force surface at all.
- **Cost:** zero new dependencies; opening-codec round trip as C1; a new
  authorized-keys config surface on the server. Slightly more provisioning than
  a bearer token (each client needs an identity — but agents/users on this
  project already have them for signing/secrets).

### C3. Noise protocol (full channel encryption without x509)

The middle path: mutual authentication + AEAD channel encryption + forward
secrecy, no certificates/PKI
([Noise spec rev 34](https://noiseprotocol.org/noise.html)). Production
precedent is strong for the *protocol*: WireGuard is Noise_IK
([wireguard.com/protocol](https://www.wireguard.com/protocol/)), libp2p uses
Noise for transport encryption ([libp2p docs](https://libp2p.io/docs/noise/)),
noiseprotocol.org lists WhatsApp/Lightning/I2P as adopters
([noiseprotocol.org](https://noiseprotocol.org/)), and Radicle — the closest
VCS-native comparable — uses Noise XK for peer connections
([protocol guide](https://radicle.dev/guides/protocol), lower-confidence cite,
page 403'd).

- **The `snow` crate** ([docs.rs](https://docs.rs/snow/latest/snow/),
  [repo](https://github.com/mcginty/snow)), v0.10.0: transport-agnostic
  (`write_message`/`read_message` over caller-owned buffers — works fine over
  blocking `TcpStream`), messages capped at 65535 bytes (the spec's bound), so a
  thin re-framing layer must segment the wire stream (the wire's existing frames
  can exceed 64 KiB — `SC_PACK_CHUNK` defaults to 1 MiB — so segmentation is at
  the Noise layer, invisible to `wire.rs`).
- **Measured dependency cost:** 37 crates in a scratch project, but only
  **9 new** vs this repo's `Cargo.lock`
  (`aes aes-gcm blake2 ctr ghash polyval ring snow untrusted`) — the smallest
  marginal footprint of any encrypting option, because snow's defaults are the
  same RustCrypto crates `crates/crypto` already pulls (chacha20poly1305,
  curve25519-dalek family, sha2).
- **Two honest strikes:** (1) snow's own README: "This library has not received
  any formal audit" ([repo](https://github.com/mcginty/snow)); no stated MSRV.
  (2) **Measured surprise:** snow 0.10.0's default build *compiles `ring`*
  (C/assembly) even though ring is nominally optional — the published
  manifest's `std` feature lists `"ring/std"`, which activates the optional
  dep (verified: `cargo tree -i ring` → `ring ← snow`, and ring build dirs
  appear in `target/`). The "pure-Rust, overlaps-our-deps" pitch is therefore
  only true after feature surgery or upstream fixes.
- **Hand-rolling Noise instead:** every required primitive already lives in
  `crates/crypto` (x25519-dalek, chacha20poly1305, hkdf/sha2, blake3). But
  implementing a handshake state machine from the spec is exactly the
  hand-rolled-crypto-protocol class this project has so far refused; the spec is
  precise but the failure modes are subtle. If Noise is chosen, `snow`
  (quarantined in `crates/crypto` per the existing discipline) is the sane
  route, unaudited status acknowledged in the ADR.
- **Surface:** the same two seam functions as TLS, plus key distribution: Noise
  IK requires the client to know the server's static public key in advance
  (a TOFU/known-hosts-style pinning problem, same as TLS-with-pinning but
  without any option to fall back to CA validation later); XX exchanges statics
  in-band and pins after. Server identity could literally be an `scl-id` v2
  X25519 key — maximal reuse. Needs either a new scheme (`sc+noise://`) or an
  opening-header negotiation; `PROTOCOL_VERSION` itself can stay 3 (encryption
  wraps below the opening, as TLS would). No operator/proxy/cert ecosystem
  exists for it — a corporate operator cannot terminate Noise at nginx.

---

## Comparison

| Option | Token theft (passive sniffer) | Traffic confidentiality | Active MITM / hijack | Replay | New crates (measured vs `Cargo.lock`) | Code surface | Operator burden |
|---|---|---|---|---|---|---|---|
| Status quo (plaintext bearer) | ✗ | ✗ | ✗ | ✗ (token reusable) | 0 | 0 | 0 |
| B: reverse proxy, both legs wrapped | ✓ | ✓ | ✓ (proxied legs) | ✓ | 0 | docs only | **high** (proxy + client-side tunnel, certs) |
| C1: challenge-response | ✓ | ✗ | ✗ | ✓ per-connection | 0 | opening codec only | none |
| C2: Ed25519 nonce-signing | ✓ (no shared secret at all) | ✗ | ✗ | ✓ per-connection | 0 | opening codec + authorized-keys config | key provisioning |
| C3: Noise (snow) | ✓ | ✓ | ✓ | ✓ | 9 (unaudited; compiles ring by default) | 2 seam fns + framing + key distribution | pinning only; no proxy/cert ecosystem |
| A: rustls, ring provider, self-signed+TOFU | ✓ | ✓ | ✓ after first connect | ✓ | 14 | 2 seam fns + verifier + cert mgmt + `sc+https://` arm | none (TOFU) / PEM optional |
| A: rustls, default (aws-lc-rs) | ✓ | ✓ | ✓ | ✓ | 18 + cmake/C-toolchain at build | same | same |

`PROTOCOL_VERSION` stays 3 in **every** option — all of them sit at or below the
HTTP opening, exactly the seam ADR-0040 chose for auth. None breaks existing
`sc+http://` remotes: A and C3 arrive as new schemes; C1/C2 are negotiable at
the opening (server can accept legacy `Bearer` during transition).

## Trade-off framing for decision ticket #26

Not a decision — the realistic candidate resolutions and their consequences:

**R1 — Documentation-only (fix the proxy story, promote ssh://).**
Write the operator doc from Option B (TCP-mode termination, loopback forward,
keep tokens, **and the client-side leg** — the gap in today's guidance), and
document `ssh://` (ADR-0022) as the already-shipped confidential transport.
*Consequences:* zero code/deps; confidentiality remains entirely opt-in and
operationally expensive; the bearer token remains sniffable in every deployment
that doesn't do the full two-legged setup — i.e., most casual ones. Honest
floor, not a fix.

**R2 — Ship challenge-response now (C1, dep-free) + R1's docs; defer TLS.**
Closes the sharpest edge — a passively sniffed, indefinitely reusable
credential — with zero dependencies and an opening-codec-only change, keeping
`PROTOCOL_VERSION` at 3 and full back-compat. *Consequences:* traffic (and repo
content) stays plaintext; active MITM/hijack unaddressed; the stored token hash
becomes pass-the-hash-equivalent (must be recorded in the threat model); risk
that "we did auth hardening" dampens urgency on real confidentiality. C2
(Ed25519 nonce-signing) is a variant of this resolution with per-client
identity and no pass-the-hash cost, at slightly higher provisioning burden.

**R3 — In-binary rustls `sc+https://` (self-signed + TOFU pinning; PEM optional).**
The complete fix at the smallest crate cost that's production-credible:
~14 new crates on the ring provider (measured), blocking `rustls::Stream` at
the two seam functions, scheme already reserved by ADR-0036, wire untouched.
ACME explicitly out (async stack); operators wanting real certs supply PEM or
still front with a proxy. *Consequences:* the project's first TLS dependency
(ADR + quarantine decision required — rustls is outside the RustCrypto
quarantine); a C-toolchain build requirement via ring (or cmake via the
default provider; or an immature pure-Rust provider); ongoing tracking of the
rustls 0.23→0.24 API break. Prior art cuts against gratuitous in-binary TLS
(Vaultwarden/Garage both punt to proxies), but sc's client-side problem — a
CLI that must reach servers its operator doesn't control — is the case where
in-binary TLS is genuinely load-bearing, unlike those server-only projects.

**R4 — Noise transport (`sc+noise://` via snow).**
Smallest marginal dependency footprint (9 crates), maximal overlap with
`crates/crypto`, identity-native (server static key = an scl-id), Radicle
precedent. *Consequences:* an explicitly unaudited crate at the security
boundary; the measured ring-compiles-anyway default; no operator ecosystem
(no certs, no proxies, no corporate story); still needs TOFU-style key
distribution. Realistic only if #26 decides sc's network identity should be
scl-id keys rather than x509 — a bigger architectural bet than a transport fix.

**Staged combination (lowest-regret path visible from here):**
R2 + R1 now (both dep-free, both small), R3 later. They compose rather than
conflict: TLS wraps *below* the opening, so a challenge-response opening keeps
working unchanged inside a future `sc+https://` channel (CR then also shields
the token from a TLS-terminating middlebox/proxy operator), and the corrected
proxy/ssh docs remain the answer for operators who front services anyway. The
main thing R2 must not do is silently close ticket #25's confidentiality
question — repo *traffic* stays plaintext until R3 (or R4) ships.
