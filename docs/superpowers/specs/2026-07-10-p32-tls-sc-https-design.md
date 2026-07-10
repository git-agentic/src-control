# P32 design: in-binary TLS — `sc+https://` via rustls (`crates/tlsio`)

- **Issue:** [#39](https://github.com/git-agentic/src-control/issues/39) — closes
  audit High #1 (plaintext bearer tokens + repo traffic on `sc+http://`), part of
  the #24 audit-response map.
- **Locked upstream decisions:** #26 (transport = in-binary rustls, ring
  provider), #35 (cert/key provisioning + accept-new TOFU pinning UX), research
  in `docs/research/tls-options-sc-http.md`.
- **Decided during brainstorm (2026-07-10):**
  1. **TLS bind gate:** a non-loopback bind with `--tls` is justified iff ≥1
     serve token is configured (or `--read-only`/`--allow-public`, as today).
     TLS alone without any auth still requires an explicit `--allow-public`.
  2. **Strict-mode knob:** `SC_HTTPS_STRICT=1` environment variable, checked at
     the single client seam — matching the `SC_HTTP_TOKEN`/`SC_PACK_CHUNK`/
     `SC_SSH`/`SC_GIT` env-knob precedent, rather than threading a flag through
     every network command.

## 1. New crate: `crates/tlsio` (`scl-tlsio`)

The only crate linking `rustls` and `rcgen` (the gix→gitio / RustCrypto→crypto
quarantine precedent). rustls is pinned with `default-features = false`,
features `ring, std, tls12, logging` (~14 new crates measured vs `Cargo.lock`;
no cmake — ring needs a C compiler only). aws-lc-rs is recorded in the ADR as
the swap-in fallback provider.

`tlsio` is a workspace dependency **leaf**: it depends on no other workspace
crate (unlike its siblings vfs/gitio/crypto, which depend on core). The
dependency rule gains one edge — `repo → tlsio` — becoming
`cli → repo → {vfs, gitio, crypto, tlsio}`, with `{vfs, gitio, crypto} → core`
as before. The CLI reaches TLS functionality only through `repo` helpers
(single consumer).

Public surface:

- `TlsClientStream` / `TlsServerStream` — thin wrappers over
  `rustls::StreamOwned<…, TcpStream>` implementing `io::Read + io::Write`, with
  `get_ref()`/`get_mut()` passthrough to the inner `TcpStream` so
  `http_transport` keeps setting the P31 socket timeouts below TLS.
- `client_connect(tcp: TcpStream, host: &str, expected_pin: Option<[u8; 32]>,
  strict: bool) -> Result<(TlsClientStream, SeenPin)>` — installs the
  hand-written (~100-line) `rustls::client::danger::ServerCertVerifier`:
  - `expected_pin = Some(p)`: a leaf whose SPKI-SHA-256 ≠ `p` fails **during
    the handshake**.
  - `expected_pin = None`, `strict = true`: handshake refused
    (`UnknownHostStrict`).
  - `expected_pin = None`, accept-new: handshake completes; the observed SPKI
    hash is returned for the caller to persist and announce. No application
    byte (opening, bearer token) is written before pin disposition is settled.
  - The verifier checks the key only — names and validity windows are
    deliberately ignored (pin-only trust in v1).
- `server_stream(tcp: TcpStream, certs, key) -> Result<TlsServerStream>`.
- `load_or_mint(dir: &Path) -> Result<(certs, key, spki)>` — loads
  `cert.pem` + `key.pem` from the given dir (`.sc/serve-tls/`), or rcgen-mints
  a long-validity self-signed pair only when missing (the key IS the identity;
  key file written 0600).
- `spki_sha256(cert) -> [u8; 32]` + a `sha256:<hex>` display helper — the one
  fingerprint format used by the banner, `sc serve fingerprint`, the pin file,
  and `SC_HTTPS_FINGERPRINT`; openssl-verifiable
  (`openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256sum`).
- Its own `thiserror` enum (`Handshake`, `PinMismatch`, `UnknownHostStrict`,
  `Mint`, `Io`), converted into `repo`'s error type via `#[from]`.

## 2. Client side (`crates/repo/src/http_transport.rs`, `stdio_transport.rs`)

- `ScHttpUrl` gains `tls: bool` from the scheme. `sc+https://` keeps default
  port 8730 (one port speaks one protocol; the operator separates them).
  `open_transport` routes `sc+https://` beside the existing `sc+http://` arm.
  Existing `sc+http://` remotes keep working unchanged; `PROTOCOL_VERSION`
  stays 3.
- `HttpTransport::connect_with_token`: after the TCP connect (existing opening
  timeout logic untouched), the socket is wrapped in a small `MaybeTls` enum
  (plain / TLS) implementing `Read + Write`, chosen by the scheme; the opening
  codec, status read, and wire handshake are byte-identical over it.
- **Pin store:** `~/.config/sc/known_hosts` — `$XDG_CONFIG_HOME`, falling back
  to `$HOME/.config` — one line per `host:port`, format
  `host:port sha256:<hex>`. `SC_HTTPS_KNOWN_HOSTS` overrides the file path
  (tests, CI). Semantics:
  - **Unknown host (accept-new default):** pin silently (append), print the
    fingerprint loudly to stderr, proceed.
  - **Pin mismatch:** always hard-fail — never a prompt — naming the file, the
    stored vs seen fingerprints, and the recovery action (remove that line if
    the server key legitimately changed).
  - **`SC_HTTPS_FINGERPRINT=<spki-sha256>`:** pre-pins for this process only —
    verified against the presented cert, never persisted (CI-friendly).
  - **`SC_HTTPS_STRICT=1`:** refuse unknown hosts; an existing pin or a
    pre-pin satisfies it.

## 3. Server side (`crates/cli` serve arm, `http_transport.rs`)

- `sc serve --http <addr> <path> --tls [--tls-cert <pem> --tls-key <pem>]`.
  `--tls-cert`/`--tls-key` require `--tls` and each other; `--tls` is refused
  with `--stdio` (ssh already provides that channel's confidentiality). Without
  PEM flags, `load_or_mint(.sc/serve-tls/)` runs; regeneration happens only
  when the material is missing. The TLS startup banner prints the SPKI
  fingerprint.
- `handle_http_connection` wraps the accepted socket in `TlsServerStream`
  before the opening read; P31's whole-session read/write timeouts still apply
  (set on the inner `TcpStream`). **Amended (implementation deviation, plan-
  approved — see ADR-0042):** the `--max-connections` busy-shed does NOT send
  a status under TLS. Sending a readable busy response would require
  performing the TLS handshake on the accept thread itself, which would let
  one slow or hostile client stall every subsequent `accept()` — exactly the
  accepts-never-block property ADR-0041 exists to protect. So at the
  connection cap, a TLS connection is simply closed with no handshake and no
  status; only plaintext (`--tls` unset) connections still get the readable
  `503` written before any read. This is a deliberate, accepted asymmetry
  between the two modes, not a bug.
- New subcommand `sc serve fingerprint [<path>]`: prints the repo's
  `.sc/serve-tls/` SPKI fingerprint, **minting if missing** (so an operator can
  distribute the pin before first serve) — same `load_or_mint` path, no drift.

## 4. P29 gate tightening

`bind_is_allowed` gains a `tls` input. Non-loopback binds are allowed iff:

- `--read-only`, or
- `--allow-public`, or
- **`--tls` AND ≥1 configured serve token.**

A plaintext non-loopback bind justified only by tokens (the P29 rule) is now
**refused**, with the error naming `--tls` as the fix — the deliberate, narrow
pre-1.0 break from decision 5. Loopback binds are unchanged.
`auth_is_mandatory` keeps its fail-closed shape: on a TLS+tokens-justified
public bind, tokens are the sole justification, so removing the last token at
runtime yields `401` (the exact P29 precedent).

## 5. Tests

- **`tlsio` unit:** mint idempotence + key file perms (0600); SPKI hash
  stability across a same-key cert re-mint; verifier accept/record, mismatch
  hard-fail, strict refusal.
- **`http_transport` integration** (loopback, OS-assigned ports, existing
  harness): full TOFU lifecycle — first connect writes the pin, second connect
  is quiet, a swapped server key hard-fails, `SC_HTTPS_FINGERPRINT` pre-pin
  works and does not persist, `SC_HTTPS_STRICT=1` refuses an unknown host;
  user-PEM path; the bind-gate lattice matrix (plaintext+tokens refused,
  TLS+tokens allowed, TLS alone refused, `--read-only`/`--allow-public`
  unchanged); and the acceptance round trip — clone + push + fetch over
  `sc+https://` with a signed ~1 MiB blob under forced `SC_PACK_CHUNK`,
  byte-for-byte, zero `.sc/tmp` residue.
- **Demo:** `demo/run_tls_demo.sh` (the `run_http_auth_demo.sh` pattern, run
  twice): TLS round trip, pin-on-first-connect, mismatch hard-fail after key
  regeneration, strict + pre-pin behavior, and the tightened plaintext gate
  (tokens-only public plaintext refused; `--tls` + token accepted).

## 6. Docs

- **ADR-0042** (required — first TLS dependency): why in-binary TLS is
  load-bearing for sc's *client* (a CLI reaching servers its operator doesn't
  control — the case Vaultwarden/Garage punt); ring vs aws-lc-rs with
  aws-lc-rs as the recorded swap-in fallback; the tlsio quarantine; the
  accept-new TOFU trust model including pin-only/no-name-validation v1; ACME
  rejection (async stack).
- **CLAUDE.md:** new commands/flags, dependency rule + quarantine list updates.
- **THREAT-MODEL:** transport section rewritten for `sc+https://`.
- **Reverse-proxy guidance:** document **both legs** (server-side TCP-mode
  termination — nginx `stream` / HAProxy `mode tcp` / stunnel — AND the
  client-side tunnel, absent today); promote `ssh://` (ADR-0022) as the
  already-shipped confidential transport.

## Non-goals

ACME in-binary; CA-path validation (later, additive for PEM deployments);
challenge-response / Ed25519 nonce-signing auth (rejected on #26); Noise
transport.
