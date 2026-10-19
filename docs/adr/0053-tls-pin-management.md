# ADR-0053: TLS pin management (`sc tls`)

- **Status:** Accepted (built)
- **Date:** 2026-10-19
- **Builds on:** ADR-0042 (in-binary TLS, accept-new TOFU pinning)

## Context

ADR-0042 pins a server's SPKI hash per `host:port` in a user-level `known_hosts` file, written on first connect. The documented recovery for a changed server key was to edit that file and delete a line, and nothing listed or removed a pin. ADR-0042 named pin-management UX as a follow-on.

## Decision

`sc tls` is a thin command over the file, with no new trust semantics:

- `sc tls list [--json]`: the well-formed pins in file order, as `host:port sha256:<hex>` lines (JSON for scripts). A host pinned twice is listed twice, because a connection uses the first; a missing file or no pins prints a hint on stderr.
- `sc tls forget <host[:port]>`: removes every pin for that host and port, hostname case-insensitively, the port exact (default 8730, as in the URL). It leaves every other line (comments, malformed lines) as it was and rewrites the file atomically and durably, and only when something was removed. Forgetting an unpinned host is an error, not a silent success. A later accept-new connection (no `SC_HTTPS_STRICT`, no `SC_HTTPS_FINGERPRINT`) re-pins what it sees, as accept-new always did; under strict mode, or with a pre-pin, the host stays unpinned (strict refuses it) and `sc tls pin` is the way to set it.
- `sc tls pin <host[:port]> <sha256:hex>`: pins without connecting first (the fingerprint `sc serve fingerprint` prints), replacing any pin the host had. This is the explicit, auditable path for a deployment that distributes the pin out of band, and it works under `SC_HTTPS_STRICT=1`.
- `sc tls path`: the file in effect (`SC_HTTPS_KNOWN_HOSTS`, else `$XDG_CONFIG_HOME/sc/known_hosts`, else `~/.config/sc/known_hosts`).

Host and port parse as an `sc+https://` URL's authority does, so a pin names what a connection looks up: a host with whitespace, `/` or `#` is refused, the host is stored lowercase, and connection lookup compares the host case-insensitively (the port exactly). Every write to the pin file, including the first-connect append, takes an advisory lock on `<file>.lock` (`File::lock`: `flock` on unix, `LockFileEx` on Windows), so concurrent `sc` processes cannot lose or resurrect a pin; a pin file that is a symlink (a shared or dotfile-managed store) is followed, so an update replaces the target and the link survives; a bare relative file name is anchored at the working directory for the durable write. Bad input (not 32 bytes of hex, an empty host, a bad port) is refused before the file is touched or created.

The pin-mismatch error names `sc tls pin` (which works under strict mode) first and `sc tls forget` with a non-strict reconnect second; the strict-unknown-host error names `sc tls pin`.

## Not decided here

CA-path validation (a PEM-provisioned alternative to pinning) and certificate-name validation are unchanged and remain follow-ons; this ADR adds no trust path.

## Tests

`tls_pins` unit tests (list order and duplicates, case-insensitive port-exact forget, comments and junk preserved, set_pin replace/append/create with a missing final newline, host:port parsing) and `crates/cli/tests/tls_pins_cli.rs` (the pin, list, JSON, re-pin, forget and path flow through the binary; refused inputs leave no file).
