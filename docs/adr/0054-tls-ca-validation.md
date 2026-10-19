# ADR-0054: CA-path validation for `sc+https://`

- **Status:** Accepted (built)
- **Date:** 2026-10-19
- **Builds on:** ADR-0042 (in-binary TLS, accept-new TOFU pinning), ADR-0053 (pin management)

## Context

ADR-0042 shipped pin-only trust: the client pins `SHA-256(SPKI)` per host and ignores certificate names and validity. That fits a self-minted identity, but it fits a CA-issued certificate badly. A certbot/ACME certificate rotates every few weeks and usually brings a new key, so the pin breaks on each renewal (or the operator must reuse the key forever). And the first connection to any host is unverified by construction, even when the server presents a certificate a CA vouched for. ADR-0042 named CA-path validation, "an additive trust option for PEM-provisioned deployments", as a follow-on, and the server side already loads an operator PEM pair (`--tls-cert`/`--tls-key`).

## Decision

A client opts into CA validation with an environment variable, resolved once per connection by `TlsClientPolicy::from_env`:

- `SC_HTTPS_CA_FILE=<path>`: trust the CA certificates in this PEM bundle.
- `SC_HTTPS_CA=system`: trust the platform's root store (`rustls-native-certs`).

When either is set the client validates like a browser (`rustls`/webpki through `scl_tlsio::client_connect_ca`): the chain to a trusted anchor, the validity window, and that the certificate covers the name or IP address the client dialled; handshake signatures are verified as always. The handshake completes before any application byte (the HTTP opening, the bearer token) is written, as in pin mode.

- It **replaces** pinning for that connection. The pin file is neither read nor written, so a CA-validated host never accrues a pin, and `SC_HTTPS_STRICT` has no meaning.
- It **fails closed.** A CA variable that is present but empty (an unset shell variable in `SC_HTTPS_CA_FILE="$BUNDLE"`) or not valid UTF-8, a bundle that cannot be read, holds no usable CA or holds any block that is not a valid certificate, an empty system store, an unrecognized `SC_HTTPS_CA` value (only `system` is accepted), both knobs set at once, or `SC_HTTPS_FINGERPRINT` (a pin, also refused if not valid UTF-8) set together with CA trust is an error. Nothing falls back to accept-new, which would send the bearer token to an unverified host. A system store that loads some roots but reports others unreadable still validates with the roots that loaded (a smaller trust set, never a larger one) and prints a warning. CA mode does not need a pin-file location, so a missing `HOME` does not fail it.
- Pin mode is unchanged and remains the default. The server side is unchanged: `sc serve --tls-cert/--tls-key` already serves a CA-issued pair.

`scl_tlsio` stays the only crate linking rustls: `CaTrust` (`from_pem_file`, `system`) and `client_connect_ca` live there; the repo layer carries the choice as `CaSource` in `TlsClientPolicy`.

## Not decided here

Revocation (CRL/OCSP) is not checked. Per-host choice of trust mode, and a CLI flag in place of the environment variables, are additive. Client certificates (mTLS) are out of scope.

## Consequences

- A CA-issued server needs no first-connect trust and survives certificate rotation.
- `system` trusts every CA in the platform store; an operator who wants less passes a bundle with `SC_HTTPS_CA_FILE`.
- Setting `SC_HTTPS_CA*` for a self-minted (self-signed) server fails by design: a self-signed certificate is not vouched for by any CA. Use pinning for those, or put the server's certificate in a bundle that names the dialled host.

## Tests

`scl_tlsio` end to end with a throwaway CA and a leaf it issued: a certificate from the trusted CA connects by DNS name and by IP and moves data; one from another CA is rejected; one issued for a different name is rejected even though its chain is valid; a bundle with no certificate or a missing file is an error. `scl_repo`: the env resolver fails closed on every bad combination, and a CA policy against a real TLS server refuses it, never creates the pin file, and fails closed on a missing or empty bundle.
