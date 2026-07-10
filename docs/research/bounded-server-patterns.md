# Research: bounded-server patterns for `sc serve --http`

- **Ticket:** [#27 — wayfinder: bounded-server patterns for serve_http_listener](https://github.com/git-agentic/src-control/issues/27)
- **Question:** What do robust std-only (or minimal-dep) TCP servers do about
  connection bounds, idle deadlines, transfer-size caps, and accept-loop
  backoff — and what fits `serve_http_listener`?
- **Date:** 2026-07-10. Research for decision ticket #28 — this document frames
  options and costs; it does not decide.
- **Method:** primary sources only (std docs, the Rust Book, git-scm.com docs,
  git.git and Go sources at pinned tags, the OpenBSD `sshd_config` man page,
  nginx docs, libev's own documentation), cited inline; every codebase claim is
  pinned to a file:line in this repo at today's `main`.

## 0. Status quo: where each missing bound actually lives

ADR-0036 names three accepted-but-open consequences — "unbounded
thread-per-connection", "no idle-transfer watchdog", "no accept-loop backoff"
(`docs/adr/0036-http-transport.md:149-161`); `docs/THREAT-MODEL.md:91-93`
repeats them as tracked operational-hardening items. This ticket adds a fourth
that neither document names: the **aggregate pack spool is unbounded**. Where
each one lives:

- **Unbounded thread-per-connection.** `serve_http_listener`
  (`crates/repo/src/http_transport.rs:492-514`) is a bare
  `for incoming in listener.incoming()` loop that calls `std::thread::spawn`
  per accepted socket (`http_transport.rs:507`) with no counter, pool, or cap
  of any kind. Each thread runs `handle_http_connection` → `wire::serve_with_policy`,
  which loops until `Bye`/EOF — a wire connection is a **long-lived session**
  (many verbs per connection), not a one-shot request.
- **No idle-transfer watchdog.** `OPENING_READ_TIMEOUT` (30s,
  `http_transport.rs:384`) is set before the opening read
  (`http_transport.rs:530-532`) and **cleared** — `set_read_timeout(None)` —
  after the 200 status, right before the wire handoff
  (`http_transport.rs:597-599`, handoff at `:602`). Post-opening, a stalled
  client holds its thread and socket forever. No write timeout is ever set, so
  a client that stops **reading** mid-`GetPack` also parks the server thread in
  a blocking `write`.
- **Unbounded aggregate spool — and read-only connections reach it.** Both
  `PutPack` arms in `wire::serve_with_policy` spool the incoming chunk stream
  to a temp file under `.sc/tmp` before anything else: the normal arm at
  `crates/repo/src/wire.rs:724-741` and — **verified** — the read-only
  rejection arm at `wire.rs:669-683`, which calls
  `spill_pack_stream(r, transport.layout())` at `wire.rs:678` and only then
  replies `EC_READONLY`. The drain is deliberate (the client streams the whole
  pack before reading a response, so draining keeps the connection in sync —
  comment at `wire.rs:670-677`), but it means an `ro`-token client can write
  arbitrarily many bytes to the server's disk. `spill_pack_stream`
  (`wire.rs:790-798`) → `read_pack_stream` (`wire.rs:430-444`) loops over
  chunk frames with **no aggregate bound**: each frame is capped at
  `MAX_OBJECT_SIZE` (`wire.rs:362-367`), but the number of frames is not.
  `TempPackGuard` (`crates/repo/src/transport.rs:215-239`) removes the file on
  drop — on success *and* error — so this is a transient-disk-fill DoS, not a
  residue bug; `.sc/tmp` shares the repo's filesystem, so filling it degrades
  the host, and pass-1 verification (`transport.rs`, `ingest_pack_file`) only
  runs *after* the full spool.
- **No accept-loop backoff.** An accept error is logged and the loop
  `continue`s immediately (`http_transport.rs:499-505`). Under `EMFILE`/`ENFILE`
  the pending connection stays in the kernel queue, accept fails again
  instantly, and the loop hot-spins at 100% CPU — the exact pathology §4's
  sources describe.
- **The per-object cap the aggregate cap must compose with.**
  `MAX_OBJECT_SIZE = 256 MiB` (`crates/core/src/lib.rs:23`) anchors the wire
  frame length (`wire.rs:363`), the pack-record compressed length
  (`crates/core/src/pack.rs:333`), and the zstd decompressed output via a
  decode-with-limit reader (`pack.rs:345-357`). Any aggregate spool cap must
  be ≥ `MAX_OBJECT_SIZE` or a single legitimate max-size object could never
  transfer.
- **What auth already covers.** The P29 token gate runs before the 200 status
  and wire handoff (`http_transport.rs:556-590`), so an *unauthenticated*
  client on a tokened server never reaches the wire loop or the spool. Every
  bound in this document therefore hardens against (a) authenticated-but-hostile
  or buggy clients, (b) the no-token loopback / `--allow-public` postures where
  auth is off by design, and (c) accidents (hung agents, dead links).
- **TLS interaction (#26 just decided in-binary rustls in `crates/tlsio`).**
  All four candidate bounds sit at or below the accept/`TcpStream` layer:
  connection counting and accept backoff wrap `Accept` before any stream
  wrapper exists; `set_read_timeout`/`set_write_timeout` are socket options on
  the underlying `TcpStream` and keep working when the stream is wrapped in
  `rustls::StreamOwned` (a TLS read/write bottoms out in socket reads/writes
  that honor the timeout); the spool cap is a byte count inside
  `read_pack_stream`, above any transport. Nothing here conflicts with the
  listener soon wrapping streams in TLS.
- One structural constraint worth naming up front: the pre-existing `.sc/`
  single-writer `RepoLock` serializes ref updates (ADR-0036,
  `http_transport.rs:483-487`), so write concurrency is already ~1 at the
  commit point; a connection cap bounds *resources* (threads, fds, spool),
  not correctness.

---

## 1. Bounded thread pools without crates

Four std-only patterns, in increasing order of behavioral change:

### 1a. Fixed worker pool + mpsc queue (the Rust Book's own web server)

The Rust Book's final project (ch. 21, "Building a Multithreaded Web Server")
is the canonical std-only reference: a `ThreadPool::new(4)` of fixed workers,
jobs dispatched as `Box<dyn FnOnce() + Send>` over an `mpsc::channel` whose
receiver is shared as `Arc<Mutex<Receiver>>`; each worker loops
`receiver.lock().unwrap().recv()`
([The Rust Programming Language, ch. 21.2](https://doc.rust-lang.org/book/ch21-02-multithreaded.html)).
The Book states the rationale plainly:

> "We'll limit the number of threads in the pool to a small number to protect
> us from DoS attacks; if we had our program create a new thread for each
> request as it came in, someone making 10 million requests to our server
> could wreak havoc by using up all our server's resources and grinding the
> processing of requests to a halt."

**Behavior at the limit:** excess work **queues** in the channel (unbounded —
`mpsc::channel` has no capacity limit), so the thread count is bounded but the
pending-connection queue is not; a client waiting in the queue gets silence,
not a signal. **Cost:** ~100 lines including graceful shutdown (the Book's
ch. 21.3 `Drop` impl). **Fit note:** because a wire connection is a whole
session, a "job" here is the entire `handle_http_connection` call — a pool of
N workers is exactly N concurrent sessions plus an invisible unbounded queue.
The pool machinery buys nothing over a plain accept gate (1c) except the queue,
which is arguably a liability (accepted-but-unserved sockets look connected to
the client while the opening timeout hasn't even started).

### 1b. Channel-of-permits semaphore (Go's `LimitListener`, in std Rust)

Go's `golang.org/x/net/netutil.LimitListener` — "returns a Listener that
accepts at most n simultaneous connections"
([pkg.go.dev/golang.org/x/net/netutil](https://pkg.go.dev/golang.org/x/net/netutil))
— is a buffered channel used as a counting semaphore: `Accept` blocks on
`l.sem <- struct{}{}` *before* calling the inner accept, and the permit is
released when the wrapped connection is closed
([netutil/listen.go](https://github.com/golang/net/blob/master/netutil/listen.go),
`acquire`/`release`/`limitListenerConn`). The std-Rust equivalent is
`mpsc::sync_channel::<()>(N)` pre-filled with N tokens (recv = acquire,
send = release), or equivalently a `Mutex<usize>` + `Condvar` pair.
**Behavior at the limit:** the accept loop **stops accepting**; excess clients
wait in the kernel backlog (bounded by the listen backlog) and either get
served late or time out on their side. No server memory/fd is spent on waiting
clients — the key advantage over 1a's user-space queue. **Cost:** ~20-30
lines; permit release needs an RAII guard moved into the connection thread so
a panic still releases (matching the guard discipline `TempPackGuard` already
established).

### 1c. Accept-gate counting with `Arc<AtomicUsize>` + reject

Same counting idea, but non-blocking: increment on accept; if over the cap,
immediately respond and close instead of serving. Because this server has an
HTTP opening, "respond" can be a real status — `write_status` would grow a
`503 Service Unavailable` arm alongside 200/404/400/401
(`http_transport.rs:141-155`) — so the client gets a diagnosable refusal
rather than a hang. Decrement via an RAII guard in the connection thread.
**Behavior at the limit:** hard, immediate shed with a status; clients can
retry. This is closest to git-daemon's behavior (§5): when full it drops the
connection with a logged "Too many children" rather than queueing
indefinitely. **Cost:** ~15 lines + one status code + a client-side error
mapping (the client's `read_status` currently treats any non-200/401/404 as a
generic protocol error, `http_transport.rs:326-330` — a 503 should map to a
clear "server busy, retry" message).

### 1d. Hybrid: block briefly, then shed

git-daemon's actual shape (§5): when at the cap it attempts to free a slot,
`sleep(1)`, re-checks, and only then drops. A std-Rust version is a bounded
`Condvar::wait_timeout` on the 1b semaphore before falling through to 1c's
503. **Cost:** 1b + 1c combined; buys tolerance of momentary spikes at the
price of holding the accept loop (and thus *all* pending accepts) for the
grace period — a serial accept loop must not sleep long.

**What each costs in behavior, summarized:** queue (1a) = invisible latency,
unbounded pending state; block-at-accept (1b) = backpressure into the kernel
backlog, zero server state per waiting client, but also zero feedback;
reject-with-status (1c) = immediate clear signal, requires the client to
handle it; hybrid (1d) = 1b's tolerance with 1c's floor.

---

## 2. Idle/progress deadlines on long transfers

### What std gives you, exactly

`TcpStream::set_read_timeout` /
[`set_write_timeout`](https://doc.rust-lang.org/std/net/struct.TcpStream.html#method.set_read_timeout):

> "If the value specified is `None`, then `read` calls will block
> indefinitely." … "Platforms may return a different error code whenever a
> read times out as a result of setting this option. For example Unix
> typically returns an error of the kind `WouldBlock`, but Windows may return
> `TimedOut`." … "An `Err` is returned if the zero `Duration` is passed to
> this method."

(`set_write_timeout` is word-for-word symmetric for `write`.) Three
consequences for this codebase:

1. **Timeout handling must match both `ErrorKind::WouldBlock` and
   `ErrorKind::TimedOut`** — the platform split is in the std contract.
2. **The docs do not define what a timed-out read leaves behind** (partial
   reads are not addressed). For a length-prefixed framed protocol that is
   decisive: after a timeout mid-frame there is no way to resynchronize, so a
   timeout must be **fatal to the connection** (drop the socket, log, let
   `TempPackGuard` clean the spool), never retried in place. Conveniently the
   current error plumbing already does this — any `Err` out of
   `read_frame_inner` (`wire.rs:349-372`) unwinds `serve_with_policy` and the
   connection thread logs and exits (`http_transport.rs:507-511`).
3. **A per-syscall read timeout IS a progress-based idle deadline**, given the
   P25 chunked stream. The timeout applies to each blocking `read` call
   independently; `read_pack_stream` reads frame-by-frame (≤ `SC_PACK_CHUNK`,
   default 1 MiB — `wire.rs:54`), and within a frame each `read` returns
   whatever bytes arrived. So a slow-but-flowing 10 GiB transfer never trips a
   60s timeout (some bytes arrive within every 60s window), while a genuinely
   stalled peer trips it within 60s. No timer bookkeeping, no watchdog thread
   — *not clearing the timeout* (or replacing it with a longer transfer value
   at `http_transport.rs:597-599`) is the whole mechanism. An **absolute**
   whole-transfer deadline, by contrast, has to pick a number that damns slow
   links or admits long stalls, and needs real clock plumbing; progress-based
   is both cheaper and better matched to "a stalled client holds its thread
   forever".

The symmetric gap: `set_write_timeout` for the `GetPack` send path — a client
that stops reading eventually fills the socket send buffer and parks the
server in `write`. Same fix, same semantics, same fatality rule.

### Prior art

- **git-daemon** has exactly this two-phase split:
  `--init-timeout` — "Timeout (in seconds) between the moment the connection
  is established and the client request is received (typically a rather low
  value, since that should be basically immediate)" — and `--timeout` —
  "Timeout (in seconds) for specific client sub-requests. This includes the
  time it takes for the server to process the sub-request and the time spent
  waiting for the next client's request"
  ([git-scm.com/docs/git-daemon](https://git-scm.com/docs/git-daemon)).
  Both default to **unset (unlimited)**. Implementation is
  `alarm(init_timeout ? init_timeout : timeout); packet_read(...); alarm(0);`
  ([daemon.c:748-750 @ v2.50.0](https://github.com/git/git/blob/v2.50.0/daemon.c)),
  with `--timeout` forwarded to the spawned service process
  (daemon.c:472). sc's `OPENING_READ_TIMEOUT` is already the `--init-timeout`
  analogue — but git ships the knob defaulting to off, where sc hardcodes 30s
  on; the missing piece is the `--timeout` analogue for the post-opening
  session.
- **sshd `LoginGraceTime`**: "The server disconnects after this time if the
  user has not successfully logged in. If the value is 0, there is no time
  limit. The default is 120 seconds"
  ([man.openbsd.org/sshd_config](https://man.openbsd.org/sshd_config)).
  Again pre-auth-window prior art (sc's 30s opening timeout is stricter than
  sshd's 120s default); sshd deliberately has *no* post-auth idle deadline —
  idle SSH sessions are legitimate. sc's post-opening phase differs: an idle
  wire session between verbs is plausible (a slow `sc push` computing the
  want-set), so the idle number needs headroom, not aggression.

---

## 3. Aggregate spool / transfer size caps

### The directly-on-point prior art: `receive.maxInputSize`

Git's receiving side has precisely the cap sc's spool lacks:

> "receive.maxInputSize: If the size of the incoming pack stream is larger
> than this limit, then git-receive-pack will error out, instead of accepting
> the pack file. If not set or set to 0, then the size is unlimited."
> ([Documentation/config/receive.adoc @ v2.50.0](https://github.com/git/git/blob/v2.50.0/Documentation/config/receive.adoc);
> rendered at [git-scm.com/docs/git-config](https://git-scm.com/docs/git-config#Documentation/git-config.txt-receivemaxInputSize))

Two implementation details worth copying:

1. **It aborts mid-stream, not after a full spool.** The limit is passed as
   `--max-input-size` to index-pack, which checks the running byte count as it
   consumes and dies the moment it crosses:
   `if (max_input_size && consumed_bytes > max_input_size) … die("pack exceeds
   maximum allowed size (%s)")`
   ([builtin/index-pack.c:351-355 @ v2.50.0](https://github.com/git/git/blob/v2.50.0/builtin/index-pack.c)).
   The sc equivalent is a running `total` check inside `read_pack_stream`
   (`wire.rs:430-444` — the `total` counter already exists) or a cap parameter
   on `spill_pack_stream`, so a hostile stream is cut off after *cap* bytes of
   disk, not after filling the disk and then noticing.
2. **The default is unlimited.** Git ships the knob off; hosts (GitHub et al.)
   turn it on. That's a defensible default for sc too — the non-negotiable part
   is that the knob *exists* and that the error is typed/clear, not the number.

### Secondary prior art: nginx `client_max_body_size`

"Sets the maximum allowed size of the client request body… If the size in a
request exceeds the configured value, the 413 (Request Entity Too Large) error
is returned to the client." Default `1m`; "Setting size to 0 disables checking"
([nginx ngx_http_core_module docs](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size)).
Two contrasts: nginx can often reject up front from a declared
`Content-Length`, but the sc wire protocol declares no total pack length — so
sc must count-as-it-streams, like git, not check-then-read, like nginx's happy
path. And nginx's *shipped-on* small default (1 MiB) reflects a web-form
workload; a VCS pack transfer is legitimately huge, which argues for git's
off-by-default posture over nginx's.

### The sc-specific wrinkles

- **The read-only drain path needs the cap most.** `wire.rs:678` spools an
  entire pack from a client that was *always* going to be rejected. Options:
  (a) apply the same aggregate cap to the drain (bounded politeness — the
  connection survives to get its typed `EC_READONLY`), or (b) skip the drain
  and hard-close after `write_err` (the drain exists only to keep the
  connection usable post-rejection; terminating the connection is equally
  sound and spools zero bytes, at the cost of the client seeing a dropped
  connection instead of — or racing with — the typed error). git-daemon's
  general posture (close + log, §5) supports (b); the typed-error ergonomics
  P29 built support (a) with a small cap.
- **Composition with `MAX_OBJECT_SIZE`:** the cap must be ≥ 256 MiB
  (`crates/core/src/lib.rs:23`) or a single max-size object can never arrive;
  ADR-0039's accepted boundary (the cap guards transfer only, a >256 MiB local
  blob fails at the receiver) stays exactly as is — an aggregate cap layers
  above the per-object/per-frame caps, it does not replace them.
- **Disk-full today is already fail-safe but late:** a full disk surfaces as a
  write `Err` from `sink.write_all` inside `read_pack_stream`, unwinds, and
  `TempPackGuard::drop` removes the partial spool (`transport.rs:238`). The
  cap converts "fails when the *disk* is exhausted, degrading everything else
  on the volume" into "fails at a configured line with a clear error."
- `GetPack` (server → client) needs no server-side cap — the server streams
  from its own store, bounded by its own repo size; the client-side spool
  (`sync.rs`, P25) trusts a server it chose to dial. The asymmetric threat is
  the *receiving* side, both server (`PutPack`) and, lower priority, client
  (`fetch` from a hostile server — same counted-cap mechanism would slot into
  the same `read_pack_stream` if ever wanted).

---

## 4. Accept-loop backoff under fd exhaustion

### What Go does (the reference implementation)

`net/http.Server.Serve`'s accept loop sleeps with exponential backoff on
temporary accept errors — 5ms doubling to a 1s cap, reset to zero after any
successful accept
([src/net/http/server.go:3420-3451 @ go1.24.0](https://github.com/golang/go/blob/go1.24.0/src/net/http/server.go)):

```go
if ne, ok := err.(net.Error); ok && ne.Temporary() {
    if tempDelay == 0 {
        tempDelay = 5 * time.Millisecond
    } else {
        tempDelay *= 2
    }
    if max := 1 * time.Second; tempDelay > max {
        tempDelay = max
    }
    srv.logf("http: Accept error: %v; retrying in %v", err, tempDelay)
    time.Sleep(tempDelay)
    continue
}
return err
```

And `Temporary()` explicitly includes fd exhaustion — 
`func (e Errno) Temporary() bool { return e == EINTR || e == EMFILE || e == ENFILE || e.Timeout() }`
([src/syscall/syscall_unix.go:134-136 @ go1.24.0](https://github.com/golang/go/blob/go1.24.0/src/syscall/syscall_unix.go))
— so `EMFILE`/`ENFILE` get the backoff and anything non-temporary terminates
`Serve`. sc's current loop (`http_transport.rs:499-505`) is the
`continue`-with-no-sleep version of this, i.e. the busy loop.

### Why "just continue" busy-loops

libev's documentation ("The special problem of accept()ing when you can't",
[ev.pod](http://pod.tst.eu/http://cvs.schmorp.de/libev/ev.pod)) explains the
mechanism: on `EMFILE`/`ENFILE` the pending connection **stays in the kernel
queue**, so the listening socket remains readable / the next `accept` fails
again immediately, "resulting in a busy loop at 100% CPU usage" — and, worse,
the client on the other end sees an established-but-never-served connection
that may stall until *its* timeout. Its honest assessment of sleeping/retrying:
"when the program encounters an overload, it will just loop until the
situation is over. While this is a form of busy waiting, no OS offers an
event-based way to handle this situation, so it's the best one can do."

### The reserved-fd trick (libev/libuv/nginx lineage)

The same libev doc describes the active-shedding alternative: keep a spare fd
(`open("/dev/null")`) at startup; on `EMFILE`/`ENFILE`, close the spare,
`accept()` the pending connection into the freed slot, immediately close it,
reopen the spare — "This will gracefully refuse clients under typical overload
conditions." The client gets a fast RST/close instead of a hang. Cost in std
Rust: ~25 lines and a per-listener spare fd; requires distinguishing
`EMFILE`/`ENFILE` from other accept errors via `io::Error::raw_os_error`.

### Simple sleep-on-error

The floor: `thread::sleep(100ms)` on any accept error, unconditionally. Three
lines, caps the spin at ~10 retries/s, no error classification. Go's shape is
strictly better for barely more code (fast recovery from one-off errors,
capped pressure under sustained ones), and neither needs a knob.

**Interaction with §1:** a connection cap set below the process's fd headroom
largely *prevents self-inflicted* `EMFILE` (each session costs a socket + a
spool fd + store fds). Backoff remains the guard for external fd pressure and
for caps set too high — the two compose, neither replaces the other.

---

## 5. Prior art on connection limits

- **git-daemon `--max-connections`** — "Maximum number of concurrent clients,
  defaults to 32. Set it to zero for no limit"
  ([git-scm.com/docs/git-daemon](https://git-scm.com/docs/git-daemon)).
  Behavior when full, from the source
  ([daemon.c:835-884 @ v2.50.0](https://github.com/git/git/blob/v2.50.0/daemon.c)):
  `handle()` first calls `kill_some_child()` — which SIGTERMs the **oldest**
  child only if another live child shares its address (a per-address fairness
  shed: one address can't monopolize slots) — then `sleep(1)`, reaps, and if
  still full: `close(incoming); logerror("Too many children, dropping
  connection")`. So: bounded grace attempt, then hard drop with a log — the
  §1d hybrid.
- **sshd `MaxStartups`** — "Specifies the maximum number of concurrent
  **unauthenticated** connections to the SSH daemon… Alternatively, random
  early drop can be enabled by specifying the three colon separated values
  start:rate:full (e.g. '10:30:60')… The default is 10:30:100"
  ([man.openbsd.org/sshd_config](https://man.openbsd.org/sshd_config)):
  refuse with probability rate/100 (30%) once 10 unauthenticated connections
  exist, scaling linearly to refuse *all* at full (100). **The load-bearing
  distinction: it gates only the pre-auth phase** — once authenticated, a
  connection stops counting against it. The sc analogue would be a cap on
  connections still inside the opening/auth window, separate from (or instead
  of) a total-session cap; sc's 30s opening timeout already bounds how long
  each pre-auth slot can be held, which is the other half of the same defense
  (sshd pairs MaxStartups with LoginGraceTime the same way). **`MaxSessions`**
  (default 10) limits multiplexed sessions *per connection* — no sc analogue
  (one wire session per TCP connection), included for completeness.
- **tiny_http** (the minimal-dep Rust HTTP server, v0.12): its concurrency
  model is "spawn multiple worker tasks and call `server.recv()` on all of
  them" — an accept thread feeds a queue, the *user* chooses the worker count
  ([docs.rs/tiny_http](https://docs.rs/tiny_http/latest/tiny_http/)). It ships
  **no built-in connection cap or body-size cap** — bounding is explicitly the
  embedder's job (its dev-dependency on `fdlimit` for its own tests hints at
  the consequence). Minimal-dep Rust prior art, in other words, does not hand
  sc a pattern here beyond "the fixed-worker-count shape bounds naturally";
  the std-only patterns in §1 are the actual toolbox.
- **Go `netutil.LimitListener`** (§1b) — the cleanest minimal formulation:
  a counting semaphore acquired **before** accept, released on connection
  close; at the limit, accepting simply pauses and the kernel backlog absorbs
  the burst ([netutil/listen.go](https://github.com/golang/net/blob/master/netutil/listen.go)).

---

## Comparison: bounding mechanisms at the accept layer

| Mechanism | Code (std-only) | At the limit | Client sees | Fits long-lived wire sessions? |
|---|---|---|---|---|
| Rust Book worker pool + mpsc queue (§1a) | ~100 lines | Threads bounded; queue unbounded | Silent wait, opening timeout not yet started | Poor — "job" = whole session; queue is invisible pending state |
| Permit semaphore, block-at-accept (§1b, LimitListener) | ~20-30 lines | Accept pauses; kernel backlog absorbs | Slow connect, then normal service or client-side timeout | Good — zero server state per waiting client |
| `Arc<AtomicUsize>` gate + 503-and-close (§1c) | ~15 lines + status arm + client mapping | Immediate shed | Clear "busy" status, can retry | Good — explicit, diagnosable |
| git-daemon hybrid: grace, then drop (§1d) | 1b + 1c | Brief block, then shed | Delay, then drop/status | OK — grace sleep holds the serial accept loop |
| sshd MaxStartups-style pre-auth-only cap | ~20 lines (needs phase tracking) | Pre-auth connections shed (optionally probabilistically) | Refused before auth | Partial — doesn't bound authenticated sessions |

| Deadline / cap / backoff | Mechanism | Cost | Prior-art default |
|---|---|---|---|
| Opening deadline | `set_read_timeout` before opening (**exists**, 30s, `http_transport.rs:384`) | shipped | sshd LoginGraceTime 120s; git-daemon `--init-timeout` unset |
| Transfer idle deadline | Don't clear at `:597` — replace with a longer read+write timeout; timeout ⇒ drop connection | ~10 lines + WouldBlock/TimedOut mapping | git-daemon `--timeout` unset (knob ships off) |
| Aggregate spool cap | Running-count check in `read_pack_stream`/`spill_pack_stream`, abort mid-stream | ~15 lines + typed error | `receive.maxInputSize` unset = unlimited (knob ships off); must stay ≥ `MAX_OBJECT_SIZE` |
| Accept backoff | Go-style 5ms→×2→1s cap on accept error, reset on success | ~10 lines, no knob | Go net/http (hardcoded, no knob) |

---

## Framing for decision ticket #28

Not a decision — #28's question decomposed into its four knobs, each with
candidate mechanisms, prior-art-grounded defaults, knob shape, and
interactions. The four are independent (each lands without the others), and
none touches the wire protocol — `PROTOCOL_VERSION` stays 3 in every
combination; a spool-cap rejection reuses the existing typed-error reply path
(`write_err`, the same seam `EC_READONLY` used).

**Knob 1 — connection limit.**
*Mechanism candidates:* permit semaphore blocking at accept (§1b) or
atomic-count + 503-and-close (§1c); the Book's queue pool (§1a) fits this
workload worst. A P29-flavored refinement: count *opening-phase* connections
separately (sshd MaxStartups' pre-auth insight) so unauthenticated churn can't
starve authenticated sessions — but at this server's scale one total cap is
probably sufficient v1.
*Default candidate:* **32** (git-daemon's shipped default; the Book uses 4 for
a demo pool, too small for real fan-out — `sc ws run` agents pushing
concurrently are legitimate parallel clients). 0 = unlimited, git-daemon
convention.
*Knob shape:* `sc serve --http --max-connections <n>` CLI flag (git-daemon
parity; serving posture is per-invocation like `--read-only`/`--allow-public`,
not repo state — `.sc/serve-tokens.toml` holds credentials, not tuning).
*Interactions:* wire sessions are long-lived, so the cap = concurrent
*sessions*, and one stalled session consumes a slot until Knob 2's deadline
reaps it — the connection cap and the idle deadline are a package (a cap
without a deadline converts "thread exhaustion" into "slot exhaustion" against
the same stall). Cap below fd headroom also largely prevents self-inflicted
EMFILE (Knob 4).

**Knob 2 — idle/progress deadline.**
*Mechanism:* per-syscall `set_read_timeout` + `set_write_timeout` left in
place for the whole session (replacing the clear at `http_transport.rs:597-599`)
— which *is* progress-based given chunked frames (§2); timeout ⇒ log + drop
connection (frame desync makes recovery impossible; `TempPackGuard` already
cleans the spool on that unwind). Handle both `WouldBlock` and `TimedOut`.
*Default candidates:* keep 30s for the opening (stricter than sshd's 120s
LoginGraceTime, already shipped); post-opening idle on the order of
**60s–300s** — git-daemon ships its `--timeout` off, so shipping the sc knob
on-by-default is a deliberate hardening divergence to argue in #28, not
parity. The number bounds *stall length*, not transfer length: a legitimate
multi-GiB pack over a slow link makes progress within any sane window, so
"deadline × large transfers over slow links" is a non-interaction under the
progress-based design (the one real casualty would be a client that computes
for minutes *between* verbs while the server waits in `read_frame_opt` —
which argues for the generous end, e.g. 300s, or a knob).
*Knob shape:* `--timeout <secs>` on `sc serve --http` (git-daemon parity),
0 = disable.
*Interactions:* reaps the stalled sessions Knob 1's slots are hostage to;
must be set on the `TcpStream` *before* any TLS wrap so it governs the
wrapped stream's blocking reads too (#26 compose point).

**Knob 3 — aggregate spool cap.**
*Mechanism:* counted abort mid-stream in `read_pack_stream`/`spill_pack_stream`
(git's `consumed_bytes > max_input_size` shape, §3), surfacing as a typed
error the client renders clearly. Separately decide the read-only drain arm
(`wire.rs:678`): cap-the-drain (keeps the typed `EC_READONLY` ergonomics) vs
skip-drain-and-close (spools zero bytes; git-daemon's drop-posture). A small
drain cap (say one chunk-frame's worth) is a middle path: enough to keep sync
for a well-behaved client that misconfigured a token, nothing for a hostile
one.
*Default candidates:* git parity says **unlimited by default, knob available**
(`receive.maxInputSize` unset); the harder line is a large-but-finite default
(e.g. 4-16 GiB) since unlike git, sc's server may sit on the same volume as
the live repo's working tree. Floor: any value must be ≥ `MAX_OBJECT_SIZE`
(256 MiB, `crates/core/src/lib.rs:23`) — reject the configuration otherwise.
*Knob shape:* two plausible homes — a `--max-pack-size <bytes>` serve flag
(consistent with the other serve-posture flags), or repo config
(`receive.maxInputSize` is git *config*, i.e. per-receiving-repo policy; sc
has no `.sc/config` surface yet, which weighs toward the flag for now, with
the P28 follow-on `--max-object-size` operator knob as the sibling precedent).
*Interactions:* composes above (never replaces) the per-frame/per-record/
decompression caps of ADR-0039; also the only knob with a client-side twin
(fetch spool, `sync.rs`) if #28 wants symmetry later.

**Knob 4 — accept-loop backoff.**
*Mechanism:* Go's exact shape — 5ms doubling to 1s cap, reset on success
(§4) — around `http_transport.rs:499-505`; optionally the libev reserved-fd
trick on `EMFILE`/`ENFILE` specifically, to actively shed instead of stall.
The plain backoff is ~10 lines and needs no error classification; the
reserved-fd variant adds fast client-visible refusal at ~25 lines.
*Default:* hardcoded, **no knob** — Go ships it knobless; there is no tuning
story an operator needs.
*Interactions:* Knob 1 makes sustained self-inflicted fd exhaustion unlikely,
demoting this to defense against external fd pressure — the cheapest of the
four and the least urgent, worth landing regardless because it's near-free.

**A sequencing observation for #28** (framing, not a decision): Knobs 2 and 4
are small, knob-free-or-one-flag, behavior-preserving for every well-behaved
client, and close two of ADR-0036's three named boundaries outright; Knob 1
closes the third with one flag and one new status code; Knob 3 is the only one
with a genuine policy question (default value, drain posture, knob home) and
the only one this research had to *name* — ADR-0036/0040 and the threat model
do not currently list the unbounded spool as an accepted boundary, so #28
should either bound it or record it.
