# ADR-0036: sc-native HTTP transport

- **Status:** Proposed
- **Date:** 2026-07-08
- **Phase:** 26
- **Builds on:** ADR-0022 (SSH stdio wire protocol), ADR-0035 (streaming pack transfer), ADR-0028 (network Git remotes — owns http(s):// routing)

## Context

sc-native network transport exists only over ssh (ADR-0022): the client
spawns `ssh host sc serve --stdio`, needing an ssh account and daemon. The
scale-&-reach horizon's "reach" phase adds a second transport speaking the
same protocol over an HTTP-flavored TCP connection. `wire::serve` and
`WireClient` already run the whole interactive session over any
`Read`+`Write`, so the work is obtaining that pair over HTTP, not
re-implementing the protocol.

## Decision

Spec: `docs/superpowers/specs/2026-07-08-p26-http-transport-design.md`.

**Persistent-connection, dep-free** (chosen over stateless git-smart-http
and over a real HTTP-library dependency). The interactive wire session
flows over ONE keep-alive TCP connection after a minimal, hand-rolled
HTTP/1.1 opening — zero new dependencies, the way the ssh path stayed
dep-free by spawning `ssh`.

**Dedicated `sc+http://` scheme** (chosen over reusing `http://` + a flag).
P18's `http://`/`https://` → git-mirror-bridge and P12's `ssh://` →
sc-native-ssh routing stay untouched; `open_transport` gains an
`sc+http://` arm. `sc+https://` slots in when TLS lands.

- **Server** `sc serve --http <addr> <path>`: a `TcpListener`, one repo
  per server (like `--stdio`), thread-per-connection. Each connection:
  minimal-parse `POST /<repo> HTTP/1.1` + headers, reply `200`/`404`/`400`,
  then hand the raw `TcpStream` to `wire::serve()`. The `.sc/`
  single-writer lock serializes pushes; concurrent fetches are read-only.
- **Client** (`sc+http://` arm): connect a `TcpStream`, write the opening,
  map the status (`404`→NotARepo, non-200→clear error) BEFORE the wire
  handshake, then run `WireClient` verbatim. P25 client temp-spill
  (`ingest_pack_file` / `write_ids_to_temp_pack`) reused unchanged.
- **No double-framing**: after the opening the connection is raw wire
  bytes; the P25 chunk stream is the wire's own framing — no HTTP
  chunked-transfer-encoding.

## Consequences

- `sc+http://` clone/fetch/push work with no ssh account, over a plain TCP
  port, reusing the P25 streaming + client-bounding machinery verbatim.
- **Plaintext only, no TLS**: `sc+https://` deferred (TLS-dep phase or a
  fronting reverse proxy).
- **No authentication**: `sc serve --http` is unauthenticated, as
  `--stdio` delegates auth to ssh; production auth + TLS = a reverse proxy.
  The reach primitive, not a hosted-git competitor.
- **Not HTTP-proxy/CDN safe**: a strict proxy won't tunnel the
  post-opening raw protocol — the accepted cost of the persistent-
  connection model.
- Zero new dependencies; the wire protocol, streaming, and version-2
  handshake are unchanged.

## Alternatives considered

- **Stateless git-smart-http** (curl client + `sc http-backend` CGI behind
  nginx, TLS/auth free). Production-realistic and proxy-friendly, but
  requires collapsing the interactive multi-round-trip session into
  stateless single-shot ops — a protocol redesign. Deferred; the dep-free
  persistent-connection model ships reach incrementally with maximal reuse.
- **Real HTTP-library dependency** (tiny_http + ureq + rustls) for true
  HTTP semantics and https now. Rejected as the first networking
  dependency, against the dep-free grain (ssh, git, P25 all added zero).
- **Reuse `http://` + a `--sc-native` flag.** Ambiguous with P18 and a
  persisted-remote footgun; a dedicated scheme is unambiguous.
