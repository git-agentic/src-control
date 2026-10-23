# P38 F2b: smart-HTTP git transport, hooks, ref policy, admission control (plan)

Second half of slice F2 (F2a shipped the repository API, lifecycle and git runner, #301). Spec:
`docs/superpowers/specs/2026-10-22-p38-forge-design.md` ("Git transport", "Server-side Git
operations" bullets on environment, ref namespace, protection linearization, admission control,
process ownership). The threat-model pass #1 (auth, tenancy, transport, resources) merges with this
slice as a `docs/THREAT-MODEL.md` section plus the tests it names.

## Scope

Routes (outside `/api/v1`, every one authenticated and authorized by the server, then handed to
`git http-backend` as a CGI):

| Request | Needs | Notes |
|---|---|---|
| `GET /{o}/{r}.git/info/refs?service=git-upload-pack` | read | smart advertisement, protocol v0 and v2 |
| `GET /{o}/{r}.git/info/refs?service=git-receive-pack` | write | `REMOTE_USER` set only after the write check |
| `POST /{o}/{r}.git/git-upload-pack` | read | clone, fetch, fetch-by-sha, `blob:none`, shallow; gzip request bodies |
| `POST /{o}/{r}.git/git-receive-pack` | write | push; streamed; capped |
| `GET .../HEAD`, `objects/info/packs`, `objects/xx/<38 hex>`, `objects/pack/pack-<40 hex>.{pack,idx}` | read | dumb reads the recordings exercise (V#14-15, J#63) |

Anything else under `/{o}/{r}.git/` is 404; a write method other than `git-receive-pack` is 405.
The sub-path handed to the CGI is rebuilt from this whitelist, never the client's string.
Out of F2b: PR retention refs and merge (F4), branch protection rules (F4; the policy function
is the one hook point they plug into), contents/commits API (F3), per-owner quotas (default off per
spec; the admission code leaves the seam), SSH, TLS.

## Credentials and answers (recorded Gitea texts, sc-forge realm)

Tokens only, never a password: `Authorization: token T`, `Bearer T`, Basic with the token as the
password under any username (incl. `oauth2`), or the token as the username with an empty password
(J#0-26). Order: authenticate, scope, repository, permission.

| Situation | Status, body (text/plain;charset=utf-8) |
|---|---|
| no credentials | 401 `Unauthorized\n` + `WWW-Authenticate: Basic realm="sc-forge"` (+ `Cache-Control: no-store`) |
| bad / unknown / expired token, or a password | 401 `Verify\n` |
| scope missing (`read:repository` / `write:repository`), or `public-only` | 403 `Forbidden\n` |
| repository missing, not live, or no access (incl. receive-pack on a missing repo) | 404 `Repository not found` |
| read access only, receive-pack | 403 `Forbidden\n` (departure: Gitea advertises and then declines in pre-receive, recorded C#30) |
| busy (admission), disk reserve | 503 / 507, `Retry-After` on 503 |

Departures (new in `departures.json`): realm text and `cache-control` on the 401s (J#27/31, V#1/3/20/21,
K#3/4), read-only collaborator push (C#30), and the already-present K#29/39 (404 for receive-pack on a
missing repo). Content types, no-cache headers, advertisement preambles and capability lists come from
git itself and are compared as recorded (V notes); `allow-tip-sha1-in-want allow-reachable-sha1-in-want`
follow from `uploadpack.allowAnySHA1InWant=true`.

## Execution model

```text
server::handle  ── path matches /{o}/{r}.git/... ──►  transport::handle   (async)
  1 authenticate+resolve   spawn_blocking: auth, scope, repos::resolve, whitelist -> Plan | Resp
  2 admit                  global + per-repo transport slots (tokio semaphores, deadline -> 503);
                           receive-pack: free-space RESERVATION min(Content-Length, --max-pack-size) -> 507
  3 register               Lifecycle registry (repo id -> live children); refuses if the repo is closing
  4 spawn                  std::process, own process group, env scrubbed, CGI vars, rlimits
  5 stream                 request body -> bounded channel -> stdin thread (cap, idle timeout)
                           CGI stdout -> header block parse -> bounded channel -> response body
                           stderr drained (capped) and logged
  6 supervise              waitid(WNOWAIT) exit detect, deadline, client disconnect, shutdown:
                           killpg while the leader is unreaped, then reap; unregister; release slots/reservation
```

`std::process` plus threads (not `tokio::process`) so the proven waitid/killpg ordering from
`gitproc.rs` is reused: the group is signalled while the leader is still an unreaped zombie, so its
group id cannot be reused. Threads per transport are bounded by the admission cap.

CGI environment is built from scratch (`env_clear`), reusing `Git::env` plus: `GIT_PROJECT_ROOT=<repo dir by id>`,
`GIT_HTTP_EXPORT_ALL=1` (only after authentication), `PATH_INFO`, `REQUEST_METHOD`, `QUERY_STRING`
(`service=...` only), `CONTENT_TYPE` (whitelisted types), `CONTENT_LENGTH` when known (else EOF-delimited),
`HTTP_CONTENT_ENCODING` (`gzip` only), `HTTP_GIT_PROTOCOL` only when it matches
`^version=[0-9]+(:[A-Za-z0-9=_.-]*)?$` (length-capped), `REMOTE_USER` (login) only after the write check,
`REMOTE_ADDR`, and for hooks `FORGE_REPO_ID`, `FORGE_USER_ID`, `FORGE_DB`. Per-spawn config adds
`transfer.hideRefs=refs/forge/`, `uploadpack.allowFilter=true`, `uploadpack.allowAnySHA1InWant=true`,
`uploadpackfilter.allow=false` with `uploadpackfilter.blob:none.allow=true`, `receive.maxInputSize=<cap>`,
`receive.autogc=false`, `receive.fsyncObjects=true`. Resource limits in `pre_exec`: `RLIMIT_CPU`,
`RLIMIT_FSIZE`, `RLIMIT_CORE=0`.

## Hooks and ref policy

`<data>/hooks/pre-receive` is a **symlink to the `sc-forge` binary** (no shell, no quoting; `main` dispatches on
argv[0] being `pre-receive`), re-pointed at every start (the binary path can change; the e2e harness passes the real
binary path, never the test executable); `core.hooksPath` is pinned on every spawn, repository-local hooks
do not exist (`--template=`). `sc-forge hook pre-receive` reads `old new ref` lines, opens the database
read-only, and refuses (exit 1, one `refusing ...` line per ref on stderr, which git shows as `remote: ...`):

- any ref outside `refs/heads/*` and `refs/tags/*`: `refusing to update <ref>: only refs/heads/* and refs/tags/* are writable`
  (S#0-11; `refs/replace/*`, `refs/forge/*`, `refs/pull/*`, `refs/notes/*`, `refs/changes/*`, anything else);
- deleting the repository's default branch (J#62, recorded `pre-receive hook declined`);
- anything when the repository row is not `live` (generation check: the id names the directory, so a
  recreated name cannot be confused; fails closed on a database error).

Authorization is evaluated once at the start of the request (a revocation does not cancel an in-flight push);
branch protection is evaluated at the ref update, i.e. in this hook, through one policy function that F4
extends (no rules exist yet). There is **no post-receive hook**: the server stamps `updated_unix` itself after receive-pack exits 0. The hook opens the
database through a purpose-built read-only opener (`db::open_readonly`: no create, `query_only`, refuses unless
`user_version == SCHEMA_VERSION`, never takes `<data>/.lock`); a failure to open or read refuses the push (fail closed).

## Process ownership, delete, shutdown

A registry in `Lifecycle` maps repository id -> live transports (pgid, kill handle). `delete` first sets
`deleting` (new transports are refused), closes the id in the registry, kills the group of every registered
transport and waits (bounded) for them to unregister, then renames the directory. A transport that registers
after the id was closed is refused. SIGTERM/shutdown stops accepting, drains, then kills stragglers (the
existing drain deadline), then closes the database. Client disconnect kills the group.

## Admission control and limits (flags)

`--max-transports` (default 32), `--max-transports-per-repo` (8), `--git-timeout` (default 1800 s wall clock),
`--git-idle-timeout` (120 s without bytes in either direction), `--max-pack-size` (receive: default 2 GiB,
also `receive.maxInputSize`), `--max-request-bytes` for upload-pack bodies, compressed and inflated (default 16 MiB), `--min-free-bytes`
(default 1 GiB reserve), CPU limit seconds (a fixed 900 s CPU limit (a constant, not a flag)). Admission happens before any process:
slot acquisition has a deadline (503 + `Retry-After: 5`); the disk reservation is released when the push ends.
The inflated size of a gzip request body is bounded by `RLIMIT_FSIZE`/memory limits of the child plus the
timeouts; the container's cgroup limits (F5) are the hard bound and the threat model says so.

## Threat model pass #1 (written with the code)

`docs/THREAT-MODEL.md` gains "sc-forge: authentication, tenancy, transport, resources", each item pointing at a
test: credential classes (F1 tests), existence oracles (foreign token == missing repo, git and API alike),
tenant isolation (a repository id directory is the only path a transport can name; whitelist; `--git-dir` via
GIT_PROJECT_ROOT never discovery), ref-namespace attacks (`refs/replace/*` push refused, `GIT_NO_REPLACE_OBJECTS`,
`refs/forge/` hidden on both services), env/config injection (scrubbed env, pinned hooksPath, no repo config),
header/query/protocol injection (whitelists), resource exhaustion (admission, rlimits, timeouts, reservation,
slow clients, gzip), process control (groups, pgid reuse, disconnect, delete, shutdown), cross-tenant reads
(deleted-but-unpruned objects are readable by anyone with read access to that repository, by `allowAnySHA1InWant`:
stated, not hidden).

## Tests (written first)

1. Unit: path whitelist (traversal, encodings, dotfiles, `..`, `.git/config`, `objects/` shapes), credential
   extraction, CGI header parser (`Status:`, multiple headers, bare LF, oversized/malformed), env builder (no
   inheritance, protocol-version filter), hook policy (every ref class, default-branch delete, non-live row,
   DB error fails closed), registry (close-then-register refused, kill and unregister), reservation arithmetic.
2. Real `git` e2e over a socket (new `tests/e2e_git.rs`): clone, push (new branch, ff, forced with lease,
   stale lease), delete branch/tag by push, tags, fetch by sha (v0 and v2) incl. a deleted branch tip, `blob:none`,
   `--depth=1` + unshallow, gzip request bodies (`http.postBuffer` small / raw POST), all credential forms (J#0-26),
   anonymous and bad token texts, no access vs missing vs read-only, scope-limited token, `refs/replace/*` and
   `refs/pull/*` pushes refused with the recorded message, default-branch deletion refused, hidden `refs/forge/*`
   never advertised, advertisement bytes and headers (V), a push that exceeds `--max-pack-size`, 507 on a full
   reserve, 503 when slots are exhausted, client disconnect kills the group (no stray `git` processes), timeout,
   delete while a clone streams (child killed, no leftover directory), concurrent pushes to one ref (one wins),
   a hook failure leaves refs unchanged.
3. Conformance: `check` compares the recorded git command for git steps (#297); the gate adds `J`, `V`, `S`, `K`,
   `M`, `C` and `N` past their clones where the scenario needs no unbuilt route; the rest keep pinned stops in
   `slice-pending.json`. New departures listed above.

## Order of work

1. departures and the gate decision (run `check` raw, see what J/V/S/K/M/C/N need), `check` git-command comparison
2. path whitelist + git credential/answer layer (no process yet) with tests
3. hook policy + `hook` subcommand + shims + tests
4. CGI spawn/stream/supervise + registry + admission + limits, wired into `server::handle` and `Lifecycle::delete`
5. e2e git tests, then threat model text, spec "as built", README, ROADMAP
6. independent review (Opus + Sol) of the final diff; fix; PR

## Risks and open points

- Streaming through `server::handle`: the body must not be buffered for git routes; the JSON body cap path stays
  for the API. A regression test asserts a 50 MiB push streams in bounded memory.
- `git http-backend` behaviour differs across git versions (chunked/EOF-delimited request bodies, gzip handling,
  `Status:` forms). CI runs the runners' git; the minimum is 2.40. The e2e suite is the guard.
- macOS vs Linux: `waitid`, rlimits (`RLIMIT_FSIZE` semantics), `statvfs` field widths.
- The hook runs a second `sc-forge` process per push; its startup cost is paid on every push (one SQLite open).
- Disk reservation is accounting, not enforcement: a push can still exceed its reservation (bounded by
  `RLIMIT_FSIZE` and `receive.maxInputSize`); a hard guarantee needs filesystem quotas (F5).

## Decisions after independent review (Opus and Sol; these supersede any conflicting text above)

1. **Gzip.** `git http-backend` buffers an upload-pack request in RAM (`GIT_HTTP_MAX_REQUEST_BUFFER`, default
   10 MiB) and its inflate path has no expanded-byte counter, and `RLIMIT_FSIZE` does not bound pipes or heap. So
   the **server inflates gzip request bodies itself** with a hard cap on *inflated* bytes (`--max-request-bytes`),
   streams the plain bytes to the CGI and never passes `Content-Encoding`; the CGI also gets
   `GIT_HTTP_MAX_REQUEST_BUFFER` set from the flag. Gzip on `git-receive-pack` is 415 (git never gzips pushes).
2. **No post-receive; read-only hook DB** (above). The hook is a symlink; paths need no quoting; hook compares the
   default branch **case-insensitively** (as F2a's `delete_branch`) and detects a delete by an all-zero new id of any
   length; tests cover mixed-case deletion in atomic and ordinary batches with every ref asserted unchanged.
3. **Process ownership.** Each transport has exactly one supervisor thread that owns the child and signals its group
   while the leader is still an unreaped zombie (the F2a `waitid(WNOWAIT)` ordering). The registry holds a
   **cancel handle** (an atomic flag the supervisor polls, backoff 2 ms to 50 ms), never a pgid, so no one can signal a
   reused group. Registration, spawn and cancellation are serialized per transport; a cancel requested before spawn
   prevents the spawn.
4. **Registry vs delete.** Registry: `Mutex<HashMap<repo id, Slot{closed, children}>>`. `delete` (already under the
   per-repo write lock) sets `deleting`, `close(id)`, cancels every child, waits (bounded 10 s) for them to
   unregister, and **refuses to rename while any survives** (reopens the slot and reports an error). `register`
   refuses a closed slot and re-reads the row's state under the registry mutex. Transports do **not** hold the shared
   `with_read` lock (a 30-minute push would block default-branch changes and branch deletes). A push that deletes a
   branch while a PATCH makes it the default can leave `HEAD` dangling (`empty: true`); the row stays authoritative.
5. **Shutdown.** `serve` cancels every registered transport and reaps it before returning; a server killed outright
   (SIGKILL, OOM) leaves children until the next start or the container's PID namespace / systemd cgroup ends them
   (stated in the threat model).
6. **Backpressure and slow clients.** Directional progress deadlines: no request bytes for `--git-idle-timeout` while
   the child waits for input, or no response progress (the channel to the client stays full) for the same time, cancels
   the transport. Pumps are `std::thread`s using `try_send` loops that also watch the cancel flag, so a stalled reader
   cannot pin a thread past cancellation. Thread count is bounded by admission.
7. **Admission, defined.** Order: global transport slot, then per-repo slot, one `--admission-wait` deadline for both
   (default 30 s, so an agent cloning one repo many times queues instead of failing at the 9th clone; limits 64 global,
   16 per repo), then (receive-pack only) the disk reservation; slot exhaustion is 503 + `Retry-After`, reserve
   exhaustion is 507. The F2a API git gate is separate (documented). git sends pushes larger than `http.postBuffer` as
   chunked, so most pushes have no `Content-Length`: reservation starts at `--push-reserve` (default 256 MiB) and grows
   in 64 MiB steps as bytes are forwarded up to `--max-pack-size`; a step that cannot be reserved aborts the push
   (logged; the client sees a dropped connection, since the response cannot be rewritten after the upload started).
   The reservation is accounting, not enforcement (a hard guarantee needs filesystem quotas, F5).
8. **Config.** `receive.advertisePushOptions=true` (recorded V#12); push options are accepted and ignored (never
   exposed to the hook as authority). `GIT_HTTP_MAX_REQUEST_BUFFER` as above.
9. **Recorded behaviours that need departures** (added with the code): v2 advertisement has no `# service=` preamble in
   stock git (V#5 note, J#35 body); Gitea's private `cache-control` on POST results and 401s (V#16/18/1/3/20/21);
   realm text; read-only collaborator pushes (C#30, S#13) are 403 at the advertisement; **HEAD never moves on a push
   and an unborn default stays unborn after a first push to another branch** (N#15-16, N#24-28 notes: the row is the
   authority and the first-push heuristic of Gitea is not copied).
10. **Gate mechanics.** `--pending` only tolerates a SetupError at the pinned stop; recorded calls to unbuilt routes
    (J#56-57 `/tags`, K `/contents`, N#6 `/contents`) cannot be hidden. The pending file gains **`defer`** entries per
    scenario (`{"J": {"defer": [[56, "GET /api/v1/repos/acme/smart/tags"], ...]}}`): the named exchanges are executed
    but not compared (reported as deferred, identity pinned by method and path, a changed recorded call fails the
    run); an exchange that starts passing is reported so the entry can be removed. Supported scenarios and prefixes are
    decided from a raw run before coding the gate and listed in the spec; S needs an unrecorded PR creation before
    exchange 0 (F4) and stays out.
11. **`check` git-command comparison (#297)** is independent tooling and ships as its own small PR first.
12. **Spec drift and exceptions.** `FORGE_GENERATION` is replaced by the immutable id (AUTOINCREMENT, never reused);
    the spec's "as built" says so. The transport sits beside the router table: it has its own declared table
    (`transport::ROUTES`, class/scope/permission per sub-path) enumerated by a test, an explicit, recorded exception to
    "every route in `routes::ROUTES`". Only `/{o}/{r}.git/...` is served (Gitea also serves it without `.git`; Engine's
    recorded clients use `.git`). Dumb `info/refs` without `service=` is pinned 404 (git's dumb listing ignores
    `hideRefs`).
13. **Test mechanics.** No fixed sleeps: readiness barriers and bounded polling; "no stray git" asserts
    `kill(-pgid, 0) == ESRCH`; memory-boundedness is asserted by blocking the child's stdin and checking the sender
    blocks (channel bound), not RSS; real binary (not the test harness) for hook tests; explicit gzip, chunked and
    EOF-delimited request cases; run on Linux and macOS CI with git >= 2.40.
14. **Order of work (revised).** 0) `check` git-command comparison as its own PR; 1) departures + gate from a raw run;
    2) whitelist + git credential/answer layer; 3) hook + opener + symlink; 4a) minimal CGI spawn and streaming with a
    real-git clone/push e2e before anything else is built on it; 4b) registry, delete integration, shutdown; 4c)
    admission, reservation, limits, rlimits; 5) full e2e, threat model, spec, README; 6) reviews; PR.
