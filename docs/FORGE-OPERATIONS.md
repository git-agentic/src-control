# Running sc-forge

`sc-forge` is the Git forge of P38 (a Gitea-compatible replacement for Codento Engine). This guide is for whoever runs it. Design
is in `docs/superpowers/specs/2026-10-22-p38-forge-design.md`, the security boundaries in `docs/THREAT-MODEL.md` (the `sc-forge`
sections). Numbers marked *estimate* were derived from the code, not measured under load.

## Image

```sh
docker build -f crates/forge/Dockerfile -t sc-forge .       # from the repository root
bash crates/forge/docker/smoke.sh sc-forge                   # boot, healthz, create, clone, docker stop -> exit 0
```

Debian trixie with git 2.47 or newer (the server needs 2.40: `merge-tree --write-tree`, and it refuses to start on older git), no
sshd, `tini` as PID 1 (without an init process, git children that outlive a killed transport stay zombies and use up `pids.max`; outside this image use `docker run --init` or your orchestrator's equivalent), runs as uid 10001 with `/data` as the only writable volume. Base images are pinned by digest in the Dockerfile. The default command only
prints help: pass `serve ...` (below). A Debian security update of git reaches you by rebuilding the image.

Bootstrap, as Engine does it:

```sh
sc-forge admin user create --data-dir /data --username <admin> --password <pw> --email <mail> --admin --must-change-password=false
sc-forge admin user generate-access-token --data-dir /data --username <admin> --token-name bootstrap --scopes all --raw
```

## Serving

```sh
sc-forge serve --data-dir /data --listen 0.0.0.0:3000 --behind-proxy \
  --public-url https://git.example.com \
  --trusted-proxy-header X-Forwarded-For --trusted-proxies 10.0.0.0/8
```

- **TLS is not in the binary.** A non-loopback `--listen` is refused unless you pass `--behind-proxy` (a TLS-terminating proxy
  fronts it) or `--allow-plaintext`. Behind a proxy also pass `--trusted-proxy-header` and `--trusted-proxies`, otherwise every client
  shares the proxy's address and the per-source password-failure budget (30 per minute) applies to all of them together.
- **One server per data directory** (a lock file); a second one exits at once.
- **Probes.** `GET /api/healthz` (also `/healthz`) is 200 when the database and every table answer, 503 otherwise. Use it for
  liveness and readiness.
- **Flags** (defaults in `sc-forge serve --help`): connection and body limits (`--max-connections`, `--max-body-bytes`), git
  concurrency (`--git-concurrency`, `--max-transports`, `--max-transports-per-repo`, `--admission-wait`), transfer bounds
  (`--git-timeout`, `--git-idle-timeout`, `--max-pack-size`, `--max-request-bytes`, `--git-memory-limit`), disk (`--min-free-bytes`,
  `--push-reserve`), password hashing (`--argon2-concurrency`), maintenance (below) and `--shutdown-timeout`. Duration flags take
  seconds, 0 is refused where it would mean "no limit", and maintenance durations are capped at ten years.

## Stopping

SIGTERM (or SIGINT) closes the listening socket, closes idle keep-alive connections, lets requests in flight finish for up to
`--shutdown-timeout` seconds (default 30), then cancels the git transports and maintenance runs still going (SIGTERM, then SIGKILL after a second) and
waits up to 10 s for them to be reaped. Exit code 0. A second signal is ignored (only SIGKILL ends the drain early); the longest
stop is `--shutdown-timeout` + 12 s. API-side git (contents writes, merges) is not cancelled; merges are journalled and settle at the next start. Set the orchestrator's grace period to `--shutdown-timeout` plus about 15 s
(Kubernetes `terminationGracePeriodSeconds`, `docker stop -t`). The listening socket closes at once, while a load balancer
or Service takes a few seconds to stop sending traffic: add a `preStop` sleep of a few seconds. A SIGKILL is also safe: the next start kills orphaned git processes
of the data directory, removes their ref locks and quarantine directories, and settles interrupted creates, deletes and merges
(`docs/THREAT-MODEL.md`, F2a and F4c).

## Logs

One JSON object per line on stderr, shaped for Cloud Logging: `time` (RFC 3339 UTC), `severity` (`INFO`, `WARNING`, `ERROR`) and
`message`, plus fields. A `serve` that fails to start (bind, second server, migration) logs its error the same way; a Rust panic
still prints plain text. Every request except a successful health probe logs `message: "request"` with `method`, `path` (no query
string), `status`, `ms` (to the response head; a git transfer streams after it) and `source` (the client address after the trusted-proxy
rule). Headers, bodies, credentials and query strings are never logged, and a string longer than 512 bytes is cut. Operator
commands (`admin ...`) print plain text to stdout and stderr, not log lines.

## Maintenance (garbage collection)

Aborted merges, refused writes and force-pushed history leave unreferenced objects; the server collects them itself.

- `--maintenance-interval` seconds (default 86400, 0 = off) and `POST /api/v1/admin/cron/git_gc_repos` (site admin, `admin` write
  scope; 204 at once, the pass runs in the background, one at a time). Both are logged.
- Stage 1 repacks (`git gc --prune=never`), stage 2 prunes unreferenced objects older than `--gc-prune-expire` (default 14 days;
  not below twice `--git-timeout` and an hour). Writers to the repository can wait on its write gate while stage 2 runs
  (`--gc-timeout` bounds stage 1, the prune has its own 10-minute limit).
- Stage 1 needs free disk of about the repository's size plus `--min-free-bytes`; below that the repository is skipped and not pruned.
  Unreachable objects are stored loose until pruned (no cruft packs), so a history that is rewritten often costs disk for up to
  `--gc-prune-expire`.
- A pass also removes stale ref locks, commit-graph locks and quarantine directories of killed git processes, only when nothing can
  own them.

## Resource limits (cgroups)

The server bounds its own git children (timeouts, `RLIMIT_CPU`/`RLIMIT_FSIZE`, output caps, `--git-memory-limit` as `RLIMIT_DATA` on
Linux only). Those are per-process; the hard bound for the whole service is the container's cgroup. Starting points, *estimates*:

| Limit | Basis | Starting value |
|---|---|---|
| `pids.max` | per transport about 8 processes (http-backend, upload-pack or receive-pack, pack-objects or index-pack, the hook, helpers) plus up to 4 pack threads each (`pack.threads` is pinned to 4 for transports; maintenance uses 2), `--git-concurrency` x 4 for API-side git, up to `--max-connections` request threads, 64 spare | `12 x max_transports + 4 x git_concurrency + max_connections + 64` = 1376 with the defaults |
| `memory.max` | a transport needs a few hundred MiB for a large repository, a maintenance pass about 0.5 GiB more (`pack.windowMemory` 256 MiB x 2 threads), each password check holds the Argon2 memory (about 19 MiB with the crate defaults) x `--argon2-concurrency`, the server itself under 100 MiB | 4 GiB with `--max-transports 16`; scale the transports with the memory, not the other way round |
| `cpu.max` | git packing is CPU bound; no hard need | 2 to 4 CPUs |
| disk | repositories grow without a quota (per-owner quotas are not built); `--min-free-bytes` and `--push-reserve` refuse pushes before the disk fills | a volume you can grow; alert at 80% |

The default `--git-memory-limit` (8 GiB per child) is far above any sensible `memory.max / max_transports`: set it explicitly
below that quotient or the cgroup OOM-kills first. A cgroup OOM kill of a git child
behaves like any killed git process (the transfer fails, the next maintenance pass or start cleans up).

## Backup and restore

State is `/data/forge.db` (SQLite, WAL) and `/data/repos/<id>.git`. Take them together: stop the server (or take a filesystem
snapshot of the volume) so the database and the repositories are from the same moment. A restore starts the server, which
reconciles rows and directories (creates, deletes, pull-request retention refs). Not tested end to end.

## Upgrades

Migrations run forward at start and are never undone; keep a backup before upgrading. The hooks directory is rewritten at every
start. Do not run two versions against one data directory.
