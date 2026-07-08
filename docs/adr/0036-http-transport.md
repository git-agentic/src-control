# ADR-0036: sc-native HTTP transport

- **Status:** Accepted
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

## Refinements discovered during the build

- **URL form:** `sc+http://host[:port]/repo`, port defaulting to
  `DEFAULT_PORT = 8730`, parsed by `ScHttpUrl::parse`
  (`crates/repo/src/http_transport.rs:150`) — mirrors `SshUrl::parse`'s
  error style (`Error::InvalidArgument`, named URL in the message) and
  additionally rejects a host/path containing `\r`/`\n` (`http_transport.rs:176`),
  a CRLF-injection guard against `write_client_opening` interpolating
  unescaped text into the request line/header.
- **Opening codec** is four small, pure `Read`/`Write` functions —
  `write_client_opening`, `read_client_opening`, `write_status`,
  `read_status` (`http_transport.rs:59`, `:68`, `:97`, `:110`) — all routed
  through one shared `read_bounded_opening` helper (`http_transport.rs:34`)
  that reads byte-by-byte up to the `\r\n\r\n` terminator and errors out
  once the accumulator crosses `MAX_OPENING_BYTES = 8 * 1024`
  (`http_transport.rs:24`), a check-before-read bound rather than a
  fixed-size buffer read.
- **Client `HttpTransport::connect`** (`http_transport.rs:207`): opens a
  `TcpStream`, writes the client opening, then reads and maps the status
  line — `200` proceeds, `404` → `Error::NotARepo`, anything else →
  `Error::Protocol` — **before** the `WireClient::handshake` call, so a
  non-repo or malformed-response server can never be mistaken for a
  HELLO-handshake failure. The stream is split via `try_clone` into
  independent read/write halves, and the status line is read through the
  *same* `BufReader` that goes on to become the `WireClient`'s reader
  (`http_transport.rs:224`–`235`) rather than a throwaway clone — `BufReader`
  can pull more than one byte per syscall, so reading the status through a
  disposable reader risked silently swallowing the first wire-protocol
  frame byte(s) if the server ever raced ahead. `open_transport`
  (`crates/repo/src/stdio_transport.rs:324`) routes `sc+http://` to this
  path above the existing local-path fallback; `ssh://` and P18's
  `http(s)://` git-bridge routing are untouched.
- **Server** `serve_http`/`serve_http_listener`
  (`http_transport.rs:297`, `:317`): thread-per-connection —
  `TcpListener::incoming()` spawns one `std::thread` per accepted socket,
  each running `handle_http_connection` (`http_transport.rs:344`)
  end-to-end and isolated (a panic or error inside one connection is
  caught/logged to stderr and never takes down the accept loop or other
  connections). `.sc/` missing at `root` → `404` with no wire handshake
  attempted; a malformed/oversized opening → best-effort `400`. A
  `set_read_timeout(OPENING_READ_TIMEOUT = 30s)` guards the opening read
  against slow-loris stalls (byte-bounded by `MAX_OPENING_BYTES` but not
  time-bounded on its own) and is explicitly cleared
  (`http_transport.rs:376`) right after writing the `200` status and
  before handing off to `wire::serve`, so a legitimate large streamed pack
  transfer is never cut off mid-stream by the same timeout that guards the
  opening. Each connection's thread opens `LocalTransport` fresh
  (`wire::serve` inside `handle_http_connection`) — no store or lock is
  shared across threads in this module; concurrency safety rides entirely
  on the pre-existing `.sc/` single-writer `RepoLock` that `commit`/`push`
  already acquire per-root. CLI surface: `sc serve --http <addr> <path>`
  (`crates/cli/src/main.rs:274`, dispatch `:628`, handler `:2415`),
  mutually exclusive with `--stdio`.
- **No double-framing, confirmed in the server path too:** after the `200`
  status line, `handle_http_connection` hands the raw, unwrapped
  `TcpStream`/`BufReader` pair straight to `wire::serve` — the P25 chunk
  stream and P22 signature objects ride the socket with no HTTP
  `Transfer-Encoding` wrapper on either end; `demo/run_http_remote_demo.sh`
  exercises this with `SC_PACK_CHUNK=4096` over a ~1 MiB blob and a signed
  commit that verifies clean in the clone.
- **Zero new dependencies**: the whole module is `std::net`/`std::io` —
  confirmed by an empty `git diff main -- '*Cargo.toml'` at phase close.

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
- **Unbounded thread-per-connection** (accepted design consequence, not
  yet closed): `serve_http_listener` spawns one OS thread per accepted
  socket with no pool, cap, or backpressure — a connection-churn client
  can exhaust server threads/fds. Follow-on: a bounded connection pool.
- **No idle-transfer watchdog**: `OPENING_READ_TIMEOUT` is cleared once
  `wire::serve` takes over, so a client that completes the opening and
  then stalls mid-transfer holds its thread indefinitely — there is no
  timeout covering the post-opening phase. Follow-on: an idle-transfer
  watchdog distinct from the opening-read timeout.
- **No accept-loop backoff**: a sustained `EMFILE`/`ENFILE` (fd
  exhaustion) makes `listener.incoming()` yield errors back-to-back with
  no delay between retries, hot-spinning the accept loop instead of
  backing off. Follow-on: bounded backoff on repeated accept errors.

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
