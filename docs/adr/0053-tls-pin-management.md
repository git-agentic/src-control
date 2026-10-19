# ADR-0053: TLS pin management (`sc tls`)

- **Status:** Accepted (built)
- **Date:** 2026-10-19
- **Builds on:** ADR-0042 (in-binary TLS, accept-new TOFU pinning)

## Context

ADR-0042 pins a server's SPKI hash per `host:port` in a user-level `known_hosts` file, written on first connect. The documented recovery for a changed server key was to edit that file and delete a line, and nothing listed or removed a pin. ADR-0042 named pin-management UX as a follow-on.

## Decision

`sc tls` is a thin command over the file, with no new trust semantics:

- `sc tls list [--json]`: the well-formed pins in file order, as `host:port sha256:<hex>` lines (JSON for scripts). A host pinned twice is listed twice, because a connection uses the first; a missing file or no pins prints a hint on stderr.
- `sc tls forget <host[:port]>`: removes every pin for that host and port, hostname case-insensitively, the port exact (default 8730, as in the URL). It leaves every other line (comments, malformed lines) as it was and rewrites the file atomically and durably, and only when something was removed. Forgetting an unpinned host is an error, not a silent success. The next connection re-pins what it sees, as accept-new always did.
- `sc tls pin <host[:port]> <sha256:hex>`: pins without connecting first (the fingerprint `sc serve fingerprint` prints), replacing any pin the host had. This is the explicit, auditable path for a deployment that distributes the pin out of band, and it works under `SC_HTTPS_STRICT=1`.
- `sc tls path`: the file in effect (`SC_HTTPS_KNOWN_HOSTS`, else `$XDG_CONFIG_HOME/sc/known_hosts`, else `~/.config/sc/known_hosts`).

Host and port parse exactly as an `sc+https://` URL's authority does, so a pin names what a connection looks up. Bad input (not 32 bytes of hex, an empty host, a bad port) is refused before the file is touched or created.

The pin-mismatch error and the strict-unknown-host error now name these commands instead of "edit the file".

## Not decided here

CA-path validation (a PEM-provisioned alternative to pinning) and certificate-name validation are unchanged and remain follow-ons; this ADR adds no trust path.

## Tests

`tls_pins` unit tests (list order and duplicates, case-insensitive port-exact forget, comments and junk preserved, set_pin replace/append/create with a missing final newline, host:port parsing) and `crates/cli/tests/tls_pins_cli.rs` (the pin, list, JSON, re-pin, forget and path flow through the binary; refused inputs leave no file).
