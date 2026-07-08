# P26 — sc-native HTTP transport: design

**Date:** 2026-07-08
**Status:** Approved
**ADR:** 0036 (Proposed → Accepted when built)
**Horizon:** Scale & reach (P25 streaming → **P26 HTTP transport** → P27 partial clone)

## Problem

sc-native network transport exists only over ssh (P12/ADR-0022): the
client spawns `ssh host sc serve --stdio`. That needs an ssh account and
an ssh daemon. A second transport that speaks the same protocol over an
HTTP-flavored TCP connection widens reach — no ssh account, firewall-port
friendliness — and is the horizon's "reach" phase between streaming (P25)
and partial clone (P27).

## Key reuse

`wire::serve(path, &mut read, &mut write)` and `WireClient` already run the
entire interactive verb session (Hello handshake + the 8 verbs + P25 chunk
streams) over ANY `Read`+`Write` pair — ssh hands it stdin/stdout, the
tests hand it thread pipes. P26 adds a new way to OBTAIN that pair: a TCP
connection opened with a minimal HTTP/1.1 handshake. The streaming session
(PROTOCOL_VERSION 2, chunk stream, client temp-spill) rides it verbatim.

## Decided design

**Persistent-connection, dep-free** (user-decided over stateless
git-smart-http and over a real HTTP-library dependency). The interactive
wire session flows over ONE keep-alive TCP connection after a minimal
HTTP opening. Zero new dependencies — hand-rolled minimal HTTP/1.1, the
way the ssh path stayed dep-free by spawning `ssh`.

### Scheme & routing

`sc+http://host:port/repo` is sc-native HTTP — a **dedicated scheme**
(user-decided over reusing `http://` + a flag). P18's `http://`/`https://`
→ git-mirror-bridge (ADR-0028) and P12's `ssh://` → sc-native-ssh routing
are both untouched. `open_transport` (the existing scheme dispatch in
`crates/repo/src/stdio_transport.rs`) gains an `sc+http://` arm. A future
`sc+https://` slots in when TLS lands.

### Server: `sc serve --http <addr> <path>`

- Opens a `TcpListener` on `<addr>`; serves the single repo at `<path>`
  (mirrors `sc serve --stdio`'s one-repo model).
- Per accepted connection, on its own thread:
  1. Minimal-parse the request line + headers: `POST /<repo> HTTP/1.1`
     followed by headers up to the blank line. Only the request line's
     validity and the target are inspected; unknown headers are ignored.
  2. Validate the served repo exists → write a status line: `200 OK`
     (proceed), `404 Not Found` (NotARepo), or `400 Bad Request` (a
     malformed opening), each with a minimal header block + blank line.
  3. On 200, hand the raw `TcpStream` to `wire::serve()` — the wire
     session (handshake + verbs + chunk streams) flows over the same
     connection.
- **Concurrency:** thread-per-connection. The existing `.sc/`
  single-writer lock (P3) serializes pushes; concurrent fetches are
  read-only and safe. A push blocked on the lock behaves as any local
  contended writer does.

### Client: the `sc+http://` transport

- Connects a `TcpStream` to `host:port`, writes the minimal HTTP opening
  naming the repo path, reads the server's status line + headers up to the
  blank line.
- Maps the status: `200` → proceed; `404` → `Error::NotARepo`; any other
  non-200 → a clear `Error` naming the code. This gives clean HTTP-level
  error reporting BEFORE the wire handshake.
- On 200, runs `WireClient` over the same `TcpStream` exactly as the ssh
  path runs it over the child's stdio — the version handshake, every verb,
  and the P25 client-side temp-spill (`ingest_pack_file` on fetch,
  `write_ids_to_temp_pack` on push) are reused unchanged.

### No double-framing

After the HTTP opening, the connection carries the raw wire protocol. The
P25 chunk stream is the WIRE's own framing inside the connection — there
is no HTTP `Transfer-Encoding: chunked`, no re-wrapping. HTTP is only the
connection-establishment envelope.

## Boundaries (accepted, explicit)

- **Plaintext only — no TLS.** `sc+https://` is deferred (a later TLS-dep
  phase, or front `sc serve --http` with a TLS-terminating reverse proxy).
- **No authentication.** `sc serve --http` is unauthenticated, exactly as
  `sc serve --stdio` delegates auth to ssh. Production auth + TLS = a
  fronting reverse proxy. This is the reach primitive, not a hosted-git
  competitor.
- **Not HTTP-proxy/CDN safe.** A strict HTTP proxy or CDN will not tunnel
  the post-opening raw protocol — the accepted cost of the dep-free
  persistent-connection model.
- **One repo per server** (like `--stdio`); multi-repo URL-path mapping is
  out of scope.

## Testing & demo

- Unit: the HTTP opening parse — a valid `POST /<repo> HTTP/1.1` + headers
  → accepted/200; a missing repo → 404; a malformed request line / no
  blank-line terminator → 400; the client's status-line mapping
  (200 proceed, 404 → NotARepo, 500 → clear error).
- Scheme routing: `sc+http://` → the new transport; `http://`/`https://`
  still → the git bridge (P18 unchanged); `ssh://` still → sc-native ssh.
- Integration (real loopback `TcpListener` on an ephemeral port, no
  external binary — unlike ssh, HTTP needs no shim):
  - clone / fetch / push over `sc+http://127.0.0.1:PORT/repo` land
    byte-identical to the origin;
  - a streamed large-ish pack (force a small `SC_PACK_CHUNK`) rides the
    connection as many chunk frames and round-trips byte-identical;
  - a signed commit (P22) verifies clean in an `sc+http://` clone
    (signatures ride the stream);
  - two concurrent fetches succeed; a push completes (lock-serialized);
  - a clone of a nonexistent server repo surfaces `NotARepo` from the 404,
    not a wire-handshake error.
- `demo/run_http_remote_demo.sh`: start `sc serve --http 127.0.0.1:PORT
  <repo>` in the background, clone then push over `sc+http://`, prove
  round-trip + zero residue (`.sc/tmp` empty both ends), stop the server.
  Run twice; zero-residue trap.

## Out of scope

TLS / `sc+https://`; authentication; HTTP proxy/CDN compatibility;
multi-repo path-mapping; keep-alive connection pooling / reuse across
operations (one connection per clone/fetch/push); HTTP methods beyond the
single opening (no REST surface — HTTP is only the connection envelope);
the deferred P25 review Minors (`read_frame_inner` 4 GiB cap, kill-9
`.sc/tmp` orphans) unless this phase's code lands in that path.
