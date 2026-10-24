# Design: sc-forge, a Gitea-compatible Git forge (P38)

- **Date:** 2026-10-22 (revision 2, after independent design review)
- **Status:** Draft, pre-implementation (ADR-0058 is Proposed)
- **ADR:** ADR-0058 is firmed from Proposed to Accepted when the phase is built
  (ROADMAP "How a phase gets built")
- **Contract source:** `crates/forge/conformance/` (recorded from real Gitea
  1.22.6 and 1.26.2; see "Conformance") plus the client survey summarized below

## Goal

A self-hostable Git forge that a platform can swap in for Gitea by changing a
base URL and a token. It serves bare Git repositories over smart HTTP and the
subset of Gitea's `/api/v1` that two real clients use: an agent runtime that
opens, gates and merges pull requests, and a portal that provisions repos,
users and tokens and brokers Git traffic.

Success is behavioural: the same clients, unmodified, pass their own end-to-end
flows against `sc-forge`. Wire compatibility is the means, not the product.

## Non-goals (and why)

- **A web UI.** The clients are programs.
- **Actions/CI, webhooks, issues, wiki, packages, LFS, OAuth apps.** No client
  calls them. Commit statuses are posted by the client's own suite runner;
  protection can require named status contexts.
- **SSH transport (v1).** No client uses it. Follow-on: OpenSSH with
  `AuthorizedKeysCommand`, not an in-process SSH server. `user/keys` goes with it.
- **Squash and rebase merge, forks, repo/user rename.** Every merge request seen
  sends `Do: "merge"`; other values answer 422. Pull requests are same
  repository only. Rename answers 422.
- **Required approvals in branch protection.** Clients decide on reviews
  client-side.
- **High availability.** One writer process, one data volume.
- **Storing `.sc/` repos.** Hosted repos are bare Git (ADR-0058, decision 1).
- **Changing Gitea's behaviour for the better.** Where a client matches on a
  Gitea quirk (error text, status code), `sc-forge` reproduces it. Deliberate
  departures (synchronous merge among them) are listed in one place, under
  "Contract decisions from the recordings", and are enforced by a
  `departures.json` override file in the harness.

## What the clients need

Tiers decide build order. Full keys, status codes and message texts live in the
recorded fixtures, not here.

**Tier 1, the default delivery path**
- `GET /api/v1/version`, `GET /api/healthz`; `GET /api/v1/user`; `GET /api/v1/users/{u}`.
- `POST /api/v1/admin/users`, `PATCH /api/v1/admin/users/{u}`; duplicate create 422.
- `POST /api/v1/orgs`, `GET /api/v1/orgs/{o}`,
  `GET /api/v1/users/{u}/orgs/{o}/permissions` (`can_create_repository`).
- `POST|GET|DELETE /api/v1/users/{u}/tokens` (password auth; mint returns `sha1`;
  list returns `id`, `name`, `token_last_eight`).
- `POST /api/v1/orgs/{o}/repos` and `POST|GET /api/v1/user/repos` (a repo may be
  owned by a user; the recorded scope scenarios call `user/repos`, which needs
  `write:user`/`read:user`); duplicate 409 or 422 "already exists".
- `GET|PATCH|DELETE /api/v1/repos/{o}/{r}` (keys read: `full_name`, `name`,
  `empty`, `private`, `description`, `default_branch`, `permissions`).
- `PUT|DELETE /api/v1/repos/{o}/{r}/collaborators/{u}` (204).
- `GET /repos/{o}/{r}/branches/{b}` (`commit.id`).
- Git smart HTTP at `/{o}/{r}.git`.

**Tier 2, pull requests and gating**
- `POST|GET /pulls`, `GET|PATCH /pulls/{n}` (full PR object from create:
  `number`, `state`, `merged`, `merge_commit_sha`, `changed_files`, `mergeable`,
  `head.{ref,sha,repo.full_name}`, `base.{ref,sha,repo.full_name}`, `html_url`);
  `GET /pulls?state=all&head=…&limit=50` must work, and clients filter by
  `head.ref` because stock Gitea ignores `head`.
- `POST /pulls/{n}/merge` with `{"Do":"merge","head_commit_id":…}`.
- `GET|POST /pulls/{n}/reviews`, `GET /pulls/{n}/reviews/{id}/comments`,
  `GET|POST /issues/{n}/comments` (the recorded scenarios create comments; reads
  need `read:issue`, writes `write:issue`).
- `POST /statuses/{sha}`; `GET /commits/{sha}/status` (combined) and
  `GET /statuses/{sha}`.

**Tier 3, content reads and writes**
- `GET /repos/search`, `/branches`, `/git/refs/heads[/{b}]` (an array),
  `/commits` (`X-Total-Count`, paging), `/git/commits/{sha}` (+`.diff`),
  `/git/trees/{sha}?recursive=true`, `GET|POST|PUT /contents/{path}`,
  `GET /archive/{ref}.zip` and `.tar.gz` (the portal reads zip; the recorded
  scenario also checks tar.gz, which `git archive --format=tar.gz` serves).

**Tier 4, protection**
- `POST|GET|PATCH|DELETE /branch_protections` (`branch_name`, `enable_push`,
  `enable_status_check`, `status_check_contexts`).

**Client behaviours that are part of the contract**
- Auth is `Authorization: token T`; git uses Basic with the token as password
  under any username (including `oauth2`). Clients re-resolve their token once
  on 401 and replay, including POST.
- A foreign token on a private repo answers what Gitea answers (one flow asserts
  401). Where no client asserts otherwise and Gitea leaks existence, `sc-forge`
  does not (see "Existence").
- Merge outcomes are classified by case-insensitive substring: "conflict" with
  405 or 409; "try again later" with 405, with `changed_files == 0` meaning
  nothing to merge; a protection refusal contains "required status checks". A 2xx
  merge answer is not trusted; clients re-read the PR for `merged` and
  `merge_commit_sha`.
- A PR is "landed" if its frozen head is an ancestor of trunk, or the merge
  commit has one parent and a tree comparison matches. A real merge commit
  satisfies the first rule.
- Combined status lists only the latest status per context; clients do not
  deduplicate. `X-Total-Count` equals the listed count.
- `GET /commits` on an empty repo answers 409.
- Git needs fetch by SHA, including the tip of a deleted branch (recorded for
  protocol v0 and v2). Tested with git 2.54: over v0, `allowReachableSHA1InWant`
  serves a commit reachable only through a hidden `refs/forge/pull/*` ref but
  refuses a commit no ref reaches, which the recorded scenario fetches; so
  `sc-forge` sets `uploadpack.allowAnySHA1InWant=true`. This adds no exposure
  over protocol v2, which does not enforce reachability at all: any object whose
  id a reader knows is already fetchable over v2. The threat model therefore
  treats "deleted but not yet gc'd" objects as readable by anyone with read
  access to the repo. Also needed: `blob:none` filters, shallow fetch,
  `Git-Protocol: version=2`, and `push --force-with-lease=refs/heads/b:`.
- Bootstrap scripts shell into the container for `admin user create --admin
  --must-change-password=false`, `admin user change-password`, and
  `admin user generate-access-token --scopes all --raw`; `sc-forge` accepts the
  same subcommands and flags.

## Architecture

### Crate and dependency rule

New top-level adapter `crates/forge` (package `scl-forge`, binary `sc-forge`),
sibling of `cli` and `desktop`. It links `{crypto, core}` and never `repo`,
`vfs` or `gitio`: hosted repos are plain Git. **Password hashing (`argon2`),
token generation, and the constant-time compare move into `crates/crypto`**
(RustCrypto stays quarantined there; the existing `random_hex` is the RNG
entry point). `gix` is not used. rustls stays in `tlsio` and TLS is deferred.
`CLAUDE.md`'s dependency rule gains one sentence in the F1 PR:
`forge → {crypto, core}`. The crate has a library target
(`scl_forge`, the whole implementation, `#![cfg(unix)]` at its root) and a thin
binary target whose `main` is `#[cfg(unix)]` with a `#[cfg(not(unix))]` stub that
prints "sc-forge is unix-only" and exits 2, so the Windows workspace check still
compiles and `cargo test --workspace` skips the library's tests there.

New direct dependencies:

| Dependency | Why |
|---|---|
| `hyper` 1.x (`http1` only) + `hyper-util` + `tokio` (multi-thread rt, net, process, io-util, signal) | HTTP server and process supervision. `hyper` and `tokio` are already in the lockfile through `objio`; this crate adds the server and multi-thread runtime, nothing in `core`/`repo`. |
| `rusqlite` (`bundled`) | Metadata. Relational queries (PR lists, latest status per context, joins), transactions, migrations; flat files would reimplement a database. First SQLite and first C-compiled dependency in the workspace; the SBOM job must list it. |
| `argon2` (in `crates/crypto`) | Password verification on token routes. |

No `deny.toml` exists; `audit.yml` and the SBOM job are the gates. CI adds a
conformance job (Python 3 stdlib) and a `git` version check.

### Storage layout (`--data-dir`)

```
<data>/forge.db            SQLite, WAL, synchronous=FULL
<data>/repos/<id>.git      bare repositories, named by immutable repo id
<data>/hooks/              hook shims (selected per spawn)
<data>/trash/<id>.git      repos pending final deletion
<data>/tmp/                scratch (index files, archives, pinned HOME)
```

Repositories are addressed by immutable numeric id, never by owner/name; the
database maps names to ids. Deleting and recreating `acme/alpha` yields a new id
and a new directory, so a lingering process cannot see the replacement.

### Metadata (SQLite)

`users` (login, lower_login UNIQUE, kind user|org, email, password hash,
is_admin, visibility), `org_members`, `tokens` (user, name, BLAKE3 hash,
last_eight, scopes, expires_at), `repos` (id, owner, name, lower_name UNIQUE per
owner, private, description, default_branch, state creating|live|deleting),
`collaborators`, `pulls` (repo, number, head_ref, base_ref, title, body, state,
merged, merge_commit_sha, `final_head_sha` (the head frozen at merge or close), `changed_files_at_merge`,
timestamps), `merge_intents`, `reviews`, `comments`, `commit_statuses` (repo,
sha, context, state, description, target_url, id AUTOINCREMENT),
`branch_protections` (repo, branch, enable_push, enable_status_check,
status_check_contexts JSON), `mergeability_cache` (repo, base_sha, head_sha →
mergeable, changed_files), a per-repo index counter. Numbered SQL migrations run
by `serve` at startup and by `admin` **only when the database does not exist yet
or is at schema version 0** (first-run bootstrap on an empty data directory, the
documented `admin user create` then `serve` sequence); on an existing database
`admin` refuses when the schema version differs from its binary's, and an older
`serve` refuses a newer schema. `serve` never caches users or tokens across
requests, so an `admin` change is visible immediately.

### Authentication

- Tokens are 40 hex characters (the length Gitea issues; clients treat them as
  opaque), stored as BLAKE3 hashes, compared in constant time, optional expiry.
  The primitives follow ADR-0040's; `serve_tokens.rs` is file-backed and
  single-repo, so only the design carries over.
- **Credential rules per route class, enforced by the router table:**

| Route class | Accepted credential | Additional rule |
|---|---|---|
| `/users/{u}/tokens*` | Basic with the user's **password only**. A token is never accepted here, as password or header. (Recorded Gitea accepts an all-scope token as the Basic password on these routes. Whether a read-only token can mint a broader one that way was not recorded in the first pass; accepting any token here would let it, so this is a defensive departure. A read-only token as the Basic password is refused 403 in Gitea, so the defensive departure only closes the broader-scope variants.) | Authenticated user must equal `{u}`, or be a site admin authenticating with their own password (recorded: allowed in Gitea; the admin's token is 401 there). |
| `admin/*` | Token with `write:admin` (or `read:admin` for GETs), user must be site admin. | |
| Everything else | `token T`, `Bearer T`, or Basic with a **token** as password under any username, or the token as username with an empty password (recorded for git; API recordings for Bearer and token-as-username are in the follow-up scenarios). A Basic password is never tried as a user password. | Scope and actor rules below. |

  The router table is the single source of authorization: every route
  declares its class, required scope category and level, and an actor/target
  rule. A route without a declaration does not compile; a test enumerates the
  table against the fixture routes.
- **Scopes:** `all`, `read|write:{repository,user,organization,admin,issue}`,
  `public-only`. Gitea accepts `public-only` and denies private repos to such a
  token (403 on 1.22.6, 404 on 1.26.2); `sc-forge` accepts it and follows 1.22.6
  (403 `token scope is limited to public repos`), so every repo (all are private)
  is denied to it.
- **Actor rules:** a token acts as its user and is intersected with the user's
  access. Organization-scoped writes (`write:organization`, repo creation in an
  org) require the user to be an owner of that org or a site admin; a user can
  mint and delete only their own tokens; nested ids (review, comment) are
  checked against the repo in the path before use.
- **Repository access** = site admin, org owner, repo owner, or collaborator
  grant (read < write < admin). Org membership alone grants nothing. No teams.
  `POST /pulls/{n}/merge` requires write.
- **Existence.** Recorded Gitea behaviour is kept: a valid token without access
  gets 404, identical to a missing repo (API and git); a bad or unknown token
  gets 401; anonymous API calls get 403 `Only signed in user is allowed to call
  APIs.` and anonymous git gets 401 with `WWW-Authenticate: Basic realm=...`.
  Gitea leaks one case (receive-pack on a missing org repo answers 403 "Push to
  create is not enabled"); `sc-forge` answers 404 there. `repos/search` and every
  listing filter by the caller's access.
- **`private: false`** on create or PATCH is accepted, stored as true and
  returned as true. (Recorded Gitea forces it only on create and stores `false`
  from a PATCH; that is an anonymous-read hole `sc-forge` does not copy.) There
  is no anonymous read.
- **Rate limits and bind gate.** Password attempts back off exponentially per
  login and are capped per source (not a lockout; a service account must not be
  lockable by a stranger); argon2 runs under a global concurrency cap. The
  server refuses a non-loopback bind unless `--behind-proxy` or
  `--allow-plaintext` is given, and trusts a forwarded-for header only when
  `--trusted-proxy-header` names it **and** the connection's peer address is inside a
  configured `--trusted-proxies <CIDR,...>` (a forwarded-for value from any other
  peer is ignored, so a client cannot spoof its address into the rate limiter).

### Git transport

Routes: every path under `/{o}/{r}.git/` is authenticated and handed to
`http-backend`: `GET info/refs?service=…`, `POST git-upload-pack`, `POST
git-receive-pack`, and the dumb-HTTP reads (`GET HEAD`, `objects/info/packs`,
`objects/..`), which `http-backend` serves from the same repository and which
the recorded fixtures exercise; write methods other than `git-receive-pack` are
refused. The server authenticates and authorizes (read for
upload-pack, write for receive-pack), resolves the repo id from the database, and
runs **`git http-backend`** as a CGI with `GIT_PROJECT_ROOT=<data>/repos/<id>.git`
and `PATH_INFO` set to the service suffix. The CGI environment is built
explicitly (the process environment is cleared): `GIT_PROJECT_ROOT`,
`GIT_HTTP_EXPORT_ALL=1` (set only after authentication, so no
`git-daemon-export-ok` marker is needed and an unexported repo cannot leak),
`PATH_INFO`, `REQUEST_METHOD`, `QUERY_STRING`, `CONTENT_TYPE`, `CONTENT_LENGTH`
(or chunked input), `HTTP_CONTENT_ENCODING`, `HTTP_GIT_PROTOCOL` from the client's
`Git-Protocol` header when it matches `version=[0-9]+(:…)?`, `REMOTE_USER` (the
authenticated login, set only after the write check), `REMOTE_ADDR`, plus the
scrubbed variables below. This keeps Git's own advertisement
preamble, content types, no-cache headers, `Content-Encoding: gzip` request
handling and protocol v2 correct without re-implementation (verified: git 2.54
serves an advertisement from a bare repo with the root set to the repo itself,
and answers 403 for receive-pack unless `REMOTE_USER` is set, which the server
sets only after the write check). The CGI response is parsed up to its blank
line (`Status:` and headers), then the body is streamed.

- **Subprocess environment** is built from scratch for every Git spawn
  (`env_clear`): fixed `PATH`, `HOME=<data>/tmp/home`, `GIT_CONFIG_NOSYSTEM=1`,
  `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_NO_REPLACE_OBJECTS=1`, `GIT_ATTR_NOSYSTEM=1`,
  `GIT_TERMINAL_PROMPT=0`, and per-spawn config through `GIT_CONFIG_COUNT`:
  `core.hooksPath=<data>/hooks` (on **every** spawn, including `update-ref`,
  which runs `reference-transaction`), `uploadpack.allowFilter=true`,
  `uploadpack.allowAnySHA1InWant=true`, `uploadpackfilter.allow=false` with
  an explicit allow for `blob:none` only, `receive.fsckObjects=true`,
  `receive.maxInputSize`, `receive.autogc=false`, `gc.auto=0`,
  `core.useReplaceRefs=false`, and durability (`core.fsync=all`,
  `core.fsyncMethod=fsync`, `receive.fsyncObjects=true`), so a loose object or ref
  that SQLite later records as complete is on disk first. Commit-producing spawns
  (`commit-tree` for auto-init, contents writes and merges) get an explicit
  identity: `GIT_AUTHOR_NAME`/`GIT_COMMITTER_NAME` = the acting user's login and
  `GIT_AUTHOR_EMAIL`/`GIT_COMMITTER_EMAIL` = the acting user's stored email (the
  `--email` given at user creation; recorded Gitea shows the user's own address,
  `<login>@noreply.localhost` for a noreply user), falling back to
  `<login>@noreply.<public-url host>` when none is stored,
  with the acting user being the merger for merges and the authenticated writer for
  contents; server-originated commits (auto-init by a service account) use the
  creating user. No identity comes from system, global or repository config. Only the `pre-receive` and `post-receive` hook
  shims exist; the hook child receives only `FORGE_REPO_ID`, `FORGE_USER_ID`,
  `FORGE_GENERATION`, `FORGE_DB` and git's quarantine variables.
- **Ref namespace policy** (pre-receive): client pushes may write `refs/heads/*`
  and `refs/tags/*` only. `refs/replace/*`, `refs/forge/*`, `refs/pull/*`,
  `refs/notes/*` and anything else are refused. `refs/forge/` is hidden from
  advertisement of both services with `transfer.hideRefs=refs/forge/` (tested with
  git 2.54: `uploadpack.hideRefs` alone still lists it to receive-pack, and
  `receive.hideRefs` alone still lists it to upload-pack).
- **Branch protection applies to every mutation path, one policy function**
  shared by pre-receive, contents writes and merges: a protected branch refuses
  direct updates from receive-pack and contents writes when `enable_push` is
  false and refuses non-fast-forward updates and deletion always. With
  `enable_push: true` a fast-forward push is accepted, and (recorded) it is not
  gated by `enable_status_check`: the required contexts gate **merges** only,
  because a status cannot exist for a commit that has not been pushed yet. An
  operator who wants no direct pushes sets `enable_push: false`. A merge through
  a PR is allowed and has its own checks. The default branch is not protected
  unless a rule says so (Gitea behaviour). Deleting the default branch is
  refused.
- **Policy linearization:** one point per mutation path, stated so tests can
  pin it. *Authorization* (is this user allowed to write this repo) is evaluated
  once when the request starts, and a revocation does not cancel an in-flight
  push. *Branch protection* is evaluated at the moment of the ref update: the
  `pre-receive` hook for pushes (one read transaction, after the pack is
  received), and the same policy function immediately before `update-ref` for
  contents writes and merges. A new rule therefore affects any update that has
  not yet reached its ref-update point. Not coordinated beyond that.
- **PR retention:** the server keeps `refs/forge/pull/<n>/head` for every PR.
  It is created **before** the PR row is inserted (so a crash leaves at worst an
  orphan ref, never a PR whose head can be pruned), refreshed by `post-receive`
  **only while the PR is open**, frozen when the PR is closed or merged. A refresh
  by `post-receive` is a conditional database update (`state = open`, then an
  `update-ref` compare-and-swap against the value it read), and the freeze first
  sets the PR to `freezing` under the per-repo write lock, so a concurrent push
  either lands before the freeze (and is captured as the final head) or sees
  `freezing` and does not touch the ref. Freezing is ordered
  **ref first, then database**: the final head is written to the ref, then the
  SQLite transition records `final_head_sha` (merge or close) (for a merge this is
  step 7 of the merge algorithm, after the base update; the `merge_intents` row
  covers the gap). The reconciler repairs closed and merged PRs as well as open
  ones: for each it makes the ref equal the stored final head (`final_head_sha`), recreating it if missing,
  and the pre-receive hook records the head into it before allowing a deletion of
  an open PR's head branch. A startup reconciler removes `refs/forge/pull/<n>/*`
  refs with no PR row and recreates a missing ref for an open PR from its stored
  head branch. With `gc.auto=0`, no unreachable PR commit is
  pruned; maintenance gc (F5) runs with a long `--prune` window under the repo
  lock.
- **Admission control** before any git process: global and per-repo limits on
  concurrent git children, per-process wall-clock timeout, per-process
  `RLIMIT_CPU`/`RLIMIT_FSIZE`, a free-space **reservation** (not a bare check) and a
  per-owner byte quota (default off). Before spawning `receive-pack`, admission
  reserves `min(Content-Length, --max-pack-size)` (the pack cap when the body is
  chunked) against free space minus the configured reserve, and against the owner
  quota; it releases the reservation when the push ends and answers 507 `Insufficient
  Storage` when it cannot reserve, so concurrent pushes cannot each pass a check that
  together overcommit the disk. `receive.maxInputSize` bounds
  the incoming pack only, so expansion is bounded by the quota and the disk
  reserve; the container applies cgroup memory and PID limits.
- **Process ownership:** each child runs in its own process group; cancellation,
  client disconnect, timeout and shutdown kill the group and reap it; stderr is
  drained concurrently with a size cap. `serve` handles SIGTERM by refusing new
  work, draining for a bounded time, killing stragglers, then closing the
  database.

### Server-side Git operations

All plumbing against the bare repo, no working tree, same sanitized environment.
Minimum `git` 2.40 in tests; the container pins a current release
(`merge-tree --write-tree` needs 2.38 or newer).

- **Argument hygiene.** Names are checked against an allowlist first. Every ref
  or revision from a client is resolved once to a full object id with
  `rev-parse --verify --end-of-options <rev>^{commit}`; only ids reach
  `merge-tree`, `commit-tree -p`, `update-ref`, `archive`, `diff-tree`.
  `--end-of-options` precedes revisions; `--` precedes paths only, and paths are
  treated as literals with NUL-delimited output (`-z`). Output is size-capped.
- **Reads:** `for-each-ref`, `rev-parse`, `log`/`rev-list` with a fixed `-z`
  format, `cat-file`, `ls-tree -r -z`, `diff-tree`, `archive --format=zip|tar.gz`.
- **Contents write** (POST/PUT/DELETE): with `new_branch`, the protection policy applies to the
  **target** branch (a new branch has no rule), creating it from a protected base is
  allowed (recorded: 201 with `new_branch` where a write to the protected branch is
  403), and the base ref is read once and used as the CAS old value. As built (F3b, "F3b decisions"
  below): path rules, then raw `ls-tree -z` and `mktree -z` along the path (no index file), `hash-object -w`,
  `commit-tree`, then `update-ref <ref> <new> <old>` (zero old id to create). The branch must pass the
  protection policy first and again immediately before the ref update. A lost CAS rebuilds from the new tip,
  revalidates the supplied blob `sha`, and retries up to 3 times, then answers 409. Server-made commits bypass
  `receive.fsckObjects`, so the path rules above are the check (plus a refusal of `.gitmodules` and over-long
  `.gitattributes` lines, whose content `fsck` checks on pushes).
- **Per-repo write lock** serializes the server's own ref writes (contents,
  merges, PR-ref updates). It does not exclude receive-pack; the guarantees below
  come from Git's atomic ref transaction, not the lock.

### Merge

`POST /pulls/{n}/merge` with `Do: merge` (other values 422). The caller needs
write access. Steps, all on captured object ids:

1. Resolve `base_oid` and `head_oid` once. If `head_commit_id` is present and
   differs from `head_oid`, answer the recorded stale-head response.
2. If the PR is already merged or closed, answer the recorded response. If
   `head_oid` is an ancestor of `base_oid`, answer Gitea's "nothing to merge"
   form (405, "Please try again later", `changed_files` 0). A merge of a closed
   PR is 404; a retry after success is 405 `The PR is already merged`; a missing
   head branch is 404.
3. Required status check: if the base has a protection rule with
   `enable_status_check`, every context in `status_check_contexts` must have a
   latest status of `success` or `skipped` on **`head_oid`** (recorded: `skipped`
   satisfies the requirement; `warning`, `error`, `failure`, `pending`, a status
   on another sha or another context do not). A refusal is 405 with a message
   containing "Not all required status checks successful". No admin bypass in v1.
4. `git merge-tree --write-tree base_oid head_oid`: exit 0 is clean, exit 1 is a
   conflict, anything else is an internal error. Unrelated histories make
   `merge-tree` exit with a fatal status, so a `merge-base` check runs first and
   answers `409 {"message":"Merge conflict: unrelated histories"}` (recorded
   Gitea sends a body with no `message` key, which no client can classify).
   Never infer from output presence. **Deliberate
   departure:** a conflict answers `409 {"message":"Merge conflict: <paths>"}`.
   Recorded Gitea answers 405 "Please try again later" for a conflict, which is
   indistinguishable from "still checking" and makes a client retry until its
   deadline; the agent runtime already classifies 405 or 409 containing
   "conflict" as a worker-fixable conflict, so the explicit form is both
   compatible and strictly better.
5. Insert a `merge_intents` row (PR, `base_oid`, `head_oid`, `merge_oid` computed
   by `commit-tree -p base_oid -p head_oid`, state `pending`).
6. One `git update-ref --stdin` transaction: `start`, `verify refs/heads/<head>
   <head_oid>`, `update refs/heads/<base> <merge_oid> <base_oid>`, `prepare`,
   `commit`. The `verify` makes "the head I checked is the head I merged" atomic
   with the base update. If base moved, recompute once or twice (bounded), then
   answer 405 "try again later"; if the head moved, answer the stale-head
   response.
7. Mark the intent done and the PR merged (`merge_commit_sha`,
   `final_head_sha`, `changed_files_at_merge`) in one SQLite transaction; return
   200. After this the PR reads `merged: true` immediately.

**Crash recovery.** Git and SQLite cannot commit together, so the intent row is
the journal. Recovery runs at startup (before the listener accepts) and,
afterwards, only while holding the per-repo write lock, which a live merge holds
for steps 5 to 7; a read that finds a `pending` intent while the lock is held
treats the PR as not yet merged and does not touch the intent, so recovery can
never abort a merge that is still in flight. On a `pending` intent: if the base ref equals `merge_oid`, finalize the PR as merged; if it
equals `base_oid`, mark the intent aborted; otherwise (base moved on) the merge
landed if `merge_oid` is an ancestor of the base, else aborted. A retried merge
request therefore recovers the original outcome instead of reporting "nothing to
merge". The merge commit message and identity follow Gitea's (`Merge pull
request '<title>' (#<n>) from <head> into <base>`, the merging user).

**Mergeability** (`mergeable`, and `changed_files` on open PRs) is computed with
`merge-tree` and cached by `(base_sha, head_sha)`, which are content-addressed so
the cache never goes stale. Closed and merged PRs never run it. List endpoints
use the cache and compute misses under a small concurrency limit.

**PR head lifecycle.** An open PR's `head.sha` is the live branch tip (a
force-push shows immediately); a merged PR's `head.sha` is frozen at merge; a
closed PR keeps its last head through `refs/forge/pull/<n>/head`. **Deleting the head
branch closes the PR** (recorded O#6-O#10 and O#24-O#25, both Gitea versions; an earlier
version of this paragraph and of `FINDINGS.md` said the PR stays open, which the fixtures
contradict); the PR then reads `head.ref: refs/pull/<n>/head` with `head.label` the branch
name, and reopening it (201) works without the branch. Pushing the
head commit straight into base does not mark the PR merged (recorded; the
agent runtime's landing check handles a trunk that contains the commits).

### Statuses

Any caller with write on the repo may post any context (Gitea's trust boundary:
the writer is trusted, status contexts are not attestations; stated here so it is
not mistaken for one). "Latest" per context is the highest insertion id. Recorded
facts: the POST response key is `status`; the combined endpoint lists only the
latest per context (success plus failure is `failure`, success plus pending is
`pending`); the history endpoints list everything. **Departures:** unknown state
strings answer 422 (Gitea stores any string); a status POST to an unknown sha
answers 404 (both versions answer 500: an internal error is not a contract). By
the version rule (1.22.6's `state: ""` and `sha: ""` on an existing commit with no
statuses, and its `200` with empty fields for an unknown sha, are empty
answers), the combined status of an existing commit with no statuses is
`state: "pending"` with the real `sha` (1.26.2), and the combined status of an
unknown sha is 404 (1.26.2). Each has an entry in `departures.json`.

### Repository lifecycle

- **Create:** insert the row (`state=creating`), create the directory
  (`git init --bare` with the sanitized environment, `HEAD` symbolic to
  `refs/heads/<default_branch>`), optionally the initial commit (`auto_init`),
  then fsync the new repository directory and its parent `repos/` directory (and
  `trash/` on a delete rename) before the row is marked live, so a power loss
  cannot leave a live row whose directory entry never reached disk. A startup
  reconciler removes directories with no live row and completes or removes
  `creating` rows.
- **Delete:** mark `deleting` (new work for that id is rejected), terminate the
  repo's registered children, rename the directory into `trash/`, delete the row,
  then remove the trash. Hooks verify `FORGE_GENERATION` against the database so
  a straggler fails closed.
  The delete is a journaled sequence, so every crash point has a defined
  recovery, run by the startup reconciler: a `deleting` row whose directory still
  exists resumes at the rename (children are gone after a restart); a `deleting`
  row whose directory is already in `trash/` finishes by deleting the row; a
  `trash/<id>.git` with no row (crash after the row delete, or a failed
  removal) is removed; and a `deleting` row with neither directory is deleted.
  A repository name is reusable as soon as its row is gone, because directories
  are addressed by immutable id.
- **Default branch:** PATCH writes bare `HEAD` first, then the row; on a mismatch at
  startup **the row is the authority** and the reconciler resets `HEAD` from it. A first
  push to a branch other than the default leaves `empty: true` (recorded). A repo is `empty` when `HEAD` does not resolve
  (computed live). **Repository names** follow the recorded Gitea rules: pattern
  `[A-Za-z0-9._-]`, at most 100 characters, case-insensitive uniqueness per owner
  (a database index on the lower-cased name), `.` and `..` reserved, and the
  suffixes `.git`, `.wiki`, `.rss` and `.atom` rejected; a leading `.` or `-`,
  `a..b`, and names such as `api`, `admin`, `user` and `assets` are **accepted**
  (recorded 201 on 1.22.6), which is safe because repositories live on disk under
  their immutable id, never under their name. **User and organization names**
  share the URL namespace with `/api/...` and the other top-level routes, so they
  additionally reject a reserved list (the union of both versions' lists plus
  `api`, `admin`, `assets`, `user`, `login`).

### HTTP surface rules

- JSON errors in Gitea's shape `{"message": "...", "url": "<base>/api/swagger"}`
  with the recorded statuses and texts.
- Pagination: `page`, `limit` (cap 50), `X-Total-Count`, `Link` where Gitea
  sends one; ordering is pinned per route from the fixtures. Routes Gitea does
  not paginate do not paginate here.
- Limits: JSON body cap, header cap, idle timeout, global connection cap, git
  request caps (inflated size included).
- `GET /api/v1/version` answers exactly the recorded Gitea version
  (`{"version":"1.22.6"}`), because clients may sniff it and the fixture compares
  it by value; the server's identity is in a `Server: sc-forge/<version>` response
  header instead.

### CLI

```
sc-forge serve --data-dir DIR --listen ADDR --public-url URL [--behind-proxy|--allow-plaintext] [limits…]
sc-forge admin user create --username U --password P --email E [--admin] [--must-change-password=false]
sc-forge admin user change-password --username U --password P [--must-change-password=false]
sc-forge admin user generate-access-token --username U [--token-name N] [--scopes S,…] [--raw]
sc-forge admin org create --name O --owner U
sc-forge hook pre-receive|post-receive      # internal
```

`admin` operates on the data directory directly and needs no network.

### Backup and durability

The supported backup is a crash-consistent volume snapshot. SQLite WAL and Git
ref updates both survive a crash, and the merge-intent journal plus the
reconcilers repair the only cross-store gap. Copying `forge.db` alone is not a
backup (it omits WAL contents). `synchronous=FULL` and the Git fsync settings above are
kept. A restore test (kill -9 loop during pushes and merges, then reconcile and
compare) ships with F4.

## Appendix A: recorded route inventory and decisions

The fixtures record 108 distinct HTTP route shapes (method plus structurally
templated path, across scenarios A to X; derive the list with
`python3 -I crates/forge/conformance/inventory.py crates/forge/conformance/fixtures/1.22.6`). The tiers above are what the two surveyed
clients call. Every recorded route group has one decision, so no route is in the
gate by accident:

| Route group | Decision | Slice |
|---|---|---|
| `version`, `healthz`, `user`, `users/{u}`, `admin/users` (GET, POST, PATCH), tokens, org permissions | implement | F1 |
| `orgs` POST/GET, `orgs/{o}/repos` POST/GET, `user/repos` POST/GET | implement | F1, F2 |
| `repos/{o}/{r}` CRUD, `repos/search`, collaborators (GET, PUT, DELETE, `permission`) | implement | F2 |
| `branches` (list, get, DELETE under the protection policy), `branch_protections` CRUD | implement | F2, F4 |
| `tags`, `git/refs`, `git/refs/heads/*`, `git/refs/tags` | implement | F3 |
| `commits` (list, get, `.diff`, `.patch`), `git/commits`, `git/trees`, `contents` (GET, POST, PUT), `archive` zip and tar.gz | implement | F3 |
| `pulls` (create, list, get, PATCH), `pulls/{n}/merge` (POST, and GET as the is-merged probe), reviews (GET, POST), review comments, issue comments (GET, POST), `statuses`, combined `commits/{sha}/status` | implement | F4 |
| `pulls/{n}.diff`, `.patch`, `/commits`, `/files`, `reviews/{id}` GET | extra: implement in F4 if it is a few lines of `git diff`/`log`, otherwise a `skip` departure with that reason | F4 |
| Git smart and dumb HTTP under `/{o}/{r}.git/` | implement through `http-backend` | F2 |
| Teams (`orgs/{o}/teams`, `teams/{id}/members`) | out (non-goal): `skip` departures, tagged `team` | F1 |
| Web UI routes (`GET /{o}/{r}` and similar HTML pages) | out (non-goal): tagged `web`, excluded from the default gate | F1 |

A slice is not done until each of its rows is either passing `check` or carries a
reviewed departure entry; the F1 PR adds the departure entries for the `out`
rows and any `extra` rows it declines.

## Phases

Every slice ends with its conformance fixtures passing `check`, plus end-to-end
tests driving `sc-forge` with real `git`.

| # | Slice | Done when |
|---|---|---|
| F0 | Contract | Recorder harness and fixtures from Gitea 1.22.6 and 1.26.2 merged, findings reconciled into this spec, ADR-0058 reviewed. |
| F1 | Skeleton, auth, bootstrap CLI | `serve` boots; migrations; router table with per-route policy; users, orgs, tokens, scopes, the credential-rule table with negative tests (token cannot mint tokens; Alice's password cannot mint Bob's); `/version`, `/healthz`, `/user`, admin users; `admin …` parity; crypto-crate additions. |
| F2 | Repos and Git transport | Repo create/get/patch/search/delete lifecycle with reconcilers, collaborators, `branches/{b}`, `http-backend` transport with ACL, environment scrub, ref-namespace policy, admission control, process groups. Real `git`: clone, push, fetch-by-sha, `blob:none`, shallow, `--force-with-lease`, gzip request bodies, replace-ref push refused. **Threat-model pass #1 (auth, tenancy, transport, resources) merges with this slice** as a `docs/THREAT-MODEL.md` section plus the tests it names. |
| F3 | Content API | Branches, refs, commits, git commits/trees/diff, contents GET/POST/PUT with the protection policy and path rules, archive zip. |
| F4 | PRs, statuses, merge, protection | Pulls, reviews, comments, statuses, protection, merge with intents and recovery, PR retention refs. **Threat-model pass #2 (server-side writes, merge races, contents bypass)**, kill -9 restore test, protection-bypass tests across receive-pack, contents and merge. |
| F5 | Ops | Container image (current git, no sshd), cgroup limits documented, structured logs without secrets, maintenance gc, SIGTERM drain test, free-space admission test, bind-gate tests. |
| F6 | Conformance on the first deployment | The consumers' own end-to-end flows run with only the project Git host swapped. src-control's exit gate; not reproducible from this repo's CI. |

## Conformance

`crates/forge/conformance/run.py` has two modes. `record` drives real Gitea
through scenarios and writes normalized fixtures; `check` replays them against
any server. Normalization keeps identity: shas and ids become stable
placeholders (`<sha#1>`, `<sha#2>`), so two different commits stay distinct and
`merged: true` cannot match `merged: false`. `check` compares status exactly,
recorded headers, and every recorded JSON value after normalization; only keys
marked volatile (timestamps, host-bearing URLs) are type-only. Scenarios may
carry state assertions (merged after merge, `head.sha` changes after a push).
Message texts are compared by the distinctive substrings the scenario lists.

Where the two Gitea versions differ, the spec names the version `sc-forge`
follows: the older pinned one (1.22.6) unless a client needs the newer. The
fixtures replace the clients' hand-authored transcripts, several of which are
labelled authored, not recorded. CI runs `check` against the in-tree server on
every PR.

## Contract decisions from the recordings

`crates/forge/conformance/FINDINGS.md` holds every observed status, body and
header. Decisions drawn from it, beyond those stated in the sections above:

- **Version rule.** Follow 1.22.6 unless it answers 500, an empty message or a
  malformed body; then follow 1.26.2.
- **Pull requests.** `PATCH pulls/{n}` answers 201 (as Gitea does). The `head=`
  filter on the list is ignored; lists are newest first, default page 30, cap 50,
  a bad `limit` falls back to the default. Force-pushing the head moves `head.sha`
  on an open PR; **a merged PR's `head.sha` is frozen at merge** (Gitea's follows
  a recreated branch; the agent runtime compares it against a frozen landing sha,
  so frozen is the safe reading). Deleting the head branch leaves the PR open.
  Pushing the head commit straight into base does not mark the PR merged, so there
  is no manual-merge detection. Approving your own PR is 422. Unknown review
  `event` values are stored as `PENDING`.
- **Protection.** Contents writes to a protected branch answer 403 when
  `enable_push` is false (also for admins; allowed with `new_branch`, and
  allowed when `enable_push` is true even if required contexts are unmet); force pushes and deletions of a protected
  branch are refused; force pushes to unprotected branches are allowed; a merge
  through a PR is allowed. Push refusal text: `Not allowed to push to protected
  branch <name>`.
- **Refs a writer may push.** Recorded Gitea lets a write collaborator push
  `refs/replace/*`, `notes`, `changes` and custom namespaces. `sc-forge` allows
  `refs/heads/*` and `refs/tags/*` only (departure; see "Git transport").
- **Empty repos.** `commits` 409 `Git Repository is empty.`; `branches` 200 with
  body `null`; `contents` 200 `[]`. A first push to a branch other than the
  default branch leaves `empty: true` (computed from `HEAD`).
- **Names.** Duplicate repo names are case-insensitive (409). Rename answers 422
  (departure; Gitea redirects). `PATCH default_branch` naming a missing branch
  answers 422 (Gitea silently keeps the old one). Reserved-name lists apply to user
  and organization names only (union of both versions' lists plus `api`); repo
  names follow the "Repository lifecycle" rules above.
- **Messages to reproduce** (clients match on them): repo duplicate 409 `The
  repository with the same name already exists.`; user and org duplicate 422
  `user already exists [name: x]`; stale head 409 `head out of date`; protection
  push refusal text above; protection merge refusal text above.
- **Departures, in one place** (each is an entry in `departures.json`, and an
  override that stops matching an exchange fails the run): synchronous merge (no
  "still checking" 405); a conflict is 409 with "conflict" in the message, not
  405 "try again later"; unrelated histories answer a classifiable 409; `Do`
  other than `merge` is 422 (Gitea: 500 for `fast-forward-only`, other styles
  accepted); `private:false` is not stored; token routes refuse tokens and
  require the caller to be `{u}` or a password-authenticated site admin; client pushes limited to `refs/heads/*` and
  `refs/tags/*`; unknown status states are 422; repo rename is 422; `PATCH
  default_branch` to a missing branch is 422; a merged PR's head is frozen;
  receive-pack on a missing repo is 404; a status POST to an unknown sha is
  404 (recorded 500 on both). The version rule also forces entries where 1.22.6
  recorded a 500, an empty message or a malformed body and 1.26.2 is followed
  (for example `commits?sha=<unknown>` answers 404, a retried merge says `The PR
  is already merged`). Not departures: `public-only` is 403 (1.22.6) and the
  combined status of an unknown sha is `200` empty (1.22.6).

  **The gate.** sc-forge's CI gate is `fixtures/1.22.6` plus `departures.json`;
  `fixtures/1.26.2` is reference data for the version rule, not a second gate.
  The pre-receive refusal for a ref outside `refs/heads/*` and `refs/tags/*` reads
  `refusing to update <ref>: only refs/heads/* and refs/tags/* are writable`.

### F1 decisions (as built)

- **Failed credential on a token route.** `/users/{u}/tokens*` answers 401
  `invalid username or password` for every failed password (wrong password, unknown
  login, a token sent as the password, an organization name), after one full Argon2
  verification (a dummy hash for the unknown or malformed case) and a delay that
  doubles from 50 ms to 2 s per recent failure of that login. It never reports
  whether the password was a valid token. No Basic or a token header answers 401
  `Basic authentication with the user's password is required`. A source with 30
  failures in a minute is refused 429 until the window passes; a stranger's
  failures slow only wrong guesses and never block the right password. The
  readonly-token-as-password note (X#32) is a departure: 401, not Gitea's 403.
- **Ordinary routes.** A Basic password that is not a token gets 401 `auth required:
  this route accepts access tokens only`; a bad `token`/`Bearer` or token-as-username
  gets the recorded `user does not exist [uid: 0, name: ...]` (the `[uid: 0, name: ...]`
  suffix is Gitea's own and kept; name capped at 80 characters). Every `/api/v1/*` path, declared or not, authenticates before the
  route lookup, so an unauthenticated caller learns nothing about the API surface.
- **Budget and limits.** The per-source budget (30 password attempts a minute) is
  reserved before verification, so concurrent requests cannot slip under it, and a
  success returns its unit. The failure delay is applied on the async runtime, not on a
  blocking thread. A request body must arrive within 30 s of its headers (408), headers
  within 10 s, at most 1 MiB (413), at most 512 connections. The data directory is made
  `0700` and `forge.db` `0600` at creation, also for a pre-existing directory. Token
  lists are newest first (Gitea's order), ties by id. `PATCH /admin/users/{u}` writes
  only the supplied columns, so concurrent patches cannot restore an old admin flag or
  password hash. `--behind-proxy` without trusted proxies warns that all clients then
  share one failure budget.
- **Organization permissions.** `GET /users/{u}/orgs/{o}/permissions` requires that the
  caller can see the organization (a private one answers `HasOrgOrUserVisible` to
  outsiders whoever the subject is) and hides a private subject like `GET /users/{u}`.
- **`must_change_password`** (the default for `admin/users` POST, as in Gitea) refuses
  password authentication on token routes with 403; tokens are unaffected.
- **Site-admin tokens.** A token with `write:admin` can `PATCH /admin/users/{u}`
  a password and then mint that user's tokens with it: admin tokens are
  impersonation-equivalent by design, and the rule "a token cannot mint tokens"
  covers every non-admin token.
- **Organization existence.** A missing organization (404 `GetOrgByName`) and an
  invisible one (404 `HasOrgOrUserVisible`) answer differently, as recorded; the
  difference reveals that an organization name exists. Kept for client parity.
- **Not yet in F1:** the F1 slice of Appendix A is complete, except `orgs/{o}/repos`
  and `user/repos`, whose scope checks are in the table and whose handlers answer 501
  until F2. `GET /api/healthz` and `GET /healthz` both answer. Only owners exist in
  `org_members` (no member roles, no teams).

### F2a decisions (as built)

F2a is the repository half of F2 (plan: `docs/superpowers/plans/2026-10-23-p38-f2a-repos-api.md`);
the smart-HTTP transport, hooks, ref policy, admission control and threat-model pass #1 are F2b.

- **Access.** One function, `repos::resolve`, turns (caller, repository) into a permission
  (site admin or owner or org owner = Admin and owner; collaborator = its mode; else none) and
  is the only place that does; F2b's git path calls it too. A missing, not-`live` or invisible
  repository is one 404; a token restricted to `public-only` is refused 403 `token scope is
  limited to public repos` before any existence is revealed, on every repository route and on
  creation; below the route's minimum is 403. `DELETE` needs owner-level authority (an admin
  collaborator cannot delete), `PATCH` and the collaborator routes need Admin, branch delete
  needs Write.
- **Collaborators.** Only an Admin manages them; an admin collaborator may grant any mode
  including `admin`; the owner (or an owner of the owning organization) cannot be added (422);
  the target must be a user (422 `user does not exist [uid: 0, name: x]` also for an
  organization); `permission` is `read|write|admin`, default `write`. Listed in the order added.
- **Listings** (`/repos/search`, `/user/repos`, `/orgs/{o}/repos`) filter in SQL by the same
  rule; a `public-only` token sees an empty 200 with `X-Total-Count: 0`; `X-Total-Count` is the
  visible count (recorded K#55-56 counted repositories the caller cannot see; a reviewed
  departure once K runs). `sort=alpha` orders by the full name `owner/name`. An existing
  organization the caller cannot see still answers 200 with what the caller can read (a
  collaborator of a repository inside it sees it).
- **PATCH.** `description`, `website` and `default_branch` apply; `name` other than the current
  one is 422 `repository rename is not supported`; a default branch that does not exist (or is
  not a valid branch name, e.g. `main~1`) is 422; `private`, `has_*`, `allow_*` and the other
  Gitea fields are accepted, ignored and answered with fixed values. The repository object keeps
  `private: true` and `internal: false` (recorded Gitea flips both on `private:false`).
- **Object quirks kept.** The owner object nested in a repository has `active: false`,
  `login_name: ""` and `is_admin: false` (recorded), `size` is 0, `empty` is computed live from
  `HEAD`, a repository's initial commit has the message `Initial commit` and the author the
  creating user, and `README.md` is `# <name>` plus two newlines.
- **Branches.** `{b..}` is a tail capture (names contain `/`). Branch names are validated as git
  would (`refname::valid_branch`) and addressed only as `refs/heads/<name>`; deleting the default
  branch is 403 `can not delete default branch`; an empty repository lists branches as `null`.
- **Lifecycle.** `serve` holds an exclusive `flock` on `<data>/.lock`, requires git 2.40 or
  newer, then reconciles once before binding the listener. The data directory is made absolute
  once (the git children run with it as their working directory) and its layout directories are
  fsynced. A per-repository read/write lock serializes the server's operations on one id:
  delete, default-branch change and branch delete take it exclusively and re-check `live` under
  it with conditional SQL; **reads of a repository's data take it shared and re-check `live`**
  (`Lifecycle::with_read`), so a read can never straddle a delete's rename and see a
  half-vanished repository as an empty one. Creation fsyncs the whole new tree, `repos/` and the
  data directory; any failure before `live` rolls back in-process, and the `creating` row is
  deleted only after the directory was removed (a failed cleanup keeps the row, so the name
  stays blocked until the next startup finishes it). At startup **every `creating` row is rolled
  back** (the row does not record `auto_init`) and its directory is **moved to `orphans/`, not
  deleted**, as is a directory with no row at all: a restored or recreated database can
  resurrect either, and nothing the server did not just create is ever deleted. A database error
  during reconcile aborts the pass before any directory is touched on its account; a `live` row
  whose directory is missing is reported, never dropped; one repository whose `HEAD` cannot be
  repaired is reported and does not stop the server from starting.
- **Git runner.** Every spawn is `env_clear` with an explicit `--git-dir` (never discovery),
  `GIT_CEILING_DIRECTORIES`, pinned per-spawn config, its own process group (signalled while the
  leader is still an unreaped zombie, so the group id cannot be reused), a deadline, capped
  output drained by dedicated threads, and an admission slot with a deadline (503 when busy,
  `--git-concurrency`, default 8); every handler answers a busy runner 503, never 500. A read
  that fails because git failed (exit 128, a damaged repository) is an error, not an empty
  repository. Commit identity values containing control characters or angle brackets are
  refused, including in the email given to `admin/users` create and patch.
- **Search and paging.** `q` is percent-decoded (`+` is a space); every `Link` URL repeats the
  query in the recorded order (`limit`, `page`, then `q`, `sort` alphabetically). A collaborator
  `permission` of the wrong JSON type is 422, never a default grant. The default branch cannot
  be deleted through a case alias (`MAIN`), whatever the filesystem.
- **Rollout.** Migration 2 has no down path and an older `serve` refuses a newer schema, so
  rolling the binary back means restoring a pre-F2a `forge.db`; the next startup then moves
  every repository directory to `orphans/` (safe, and recoverable by restoring the database).
  Not verified against Gitea's source: `/user/repos` is scoped `write:user`/`read:user` as
  recorded (B#26, B#34); whether Gitea also requires a repository scope there is open.
- **Conformance gate.** (F2a; superseded by the F2b gate below.) `forge-check.sh` replayed `A`, `B`, `C`, `L`, `N` and `R`,
  with `C` and `N` stopping at their first `git clone`.

### F2b decisions (as built)

F2b is the git half of F2 (plan: `docs/superpowers/plans/2026-10-23-p38-f2b-git-transport.md`, with its
"Decisions after independent review"). Differences from the plan are listed last.

- **Routes.** `/{o}/{r}.git/{info/refs, git-upload-pack, git-receive-pack, HEAD, objects/info/packs, objects/xx/<38 hex>,
  objects/pack/pack-<hex>.{pack,idx}}` only, served by `git http-backend` run as a CGI; everything else under `.git/` is
  404, a wrong method 405, a dumb `info/refs` (no `service=`) 404 (git's dumb listing ignores `hideRefs`). The transport
  has its own whitelist (`transport::parse`) beside `routes::ROUTES`: an explicit, recorded exception to "every route is in
  the table". Gitea also serves the path without `.git`; sc-forge does not.
- **Order of checks** on a git request: credentials (401), method (405), scope (403), repository and existence (404),
  permission (403), then encoding (415), declared body size (413), admission (503), gzip inflation (400/413), disk
  reservation (507), process start.
  Answers are the recorded Gitea texts; the realm is `Gitea`, and 401s and RPC results carry Gitea's
  `Cache-Control: max-age=0, private, must-revalidate, no-transform`.
- **Process model.** `server::handle` routes git paths before the bounded body read. A transport is a child
  (`std::process`, own group) with a supervisor thread (exit detection by `waitid(WNOWAIT)`, `killpg` before reaping,
  deadline, cancel flag), a stdin writer, a stdout reader that parses the CGI head then streams, and a stderr tail that is
  logged when the child fails. A gzip request body is inflated whole before the spawn (cap on compressed and inflated
  bytes); other bodies go through a bounded channel fed by an async pump (size cap, idle deadline, reservation
  growth). The response body is a channel read by hyper that ends only on an explicit marker from a clean exit, and
  dropping it cancels the transport. A transport we end gets SIGTERM, then SIGKILL after 1 s. `Lifecycle::registry` maps repository id to cancel
  handles; `delete` closes the slot, cancels, waits up to 10 s and refuses to rename while a transport survives.
- **Hook.** `pre-receive` is a symlink `<data>/hooks/pre-receive` to the `sc-forge` binary (argv[0] dispatch, no shell);
  there is no post-receive hook, the server stamps `updated_unix` itself after `receive-pack` exits 0.
  `core.hooksPath` is pinned per spawn.
- **Ref policy** (`policy.rs`, shared by the hook and F2a's branch deletes): only `refs/heads/*` and `refs/tags/*` are
  writable; the default branch cannot be deleted (Unicode lower case compare); a repository that is not `live` refuses
  everything. Push options are advertised and ignored. HEAD never moves on a push: the row is the authority, an unborn
  default stays unborn (departures N#13/16/22/26).
- **Known race.** The hook reads the default branch without the per-repository lock (a push can run for 30 minutes), so a
  `PATCH default_branch` racing a push that deletes the new default can leave `HEAD` and the row naming a branch that
  no longer exists (`empty: true` until the next push or PATCH). The row stays the authority; closing it needs a
  lease between receive-pack and the PATCH, which F4's branch protection will need anyway.
- **Flags.** `--max-transports` (64), `--max-transports-per-repo` (16), `--admission-wait` (30 s), `--git-timeout`
  (1800 s), `--git-idle-timeout` (120 s), `--max-pack-size` (2 GiB), `--max-request-bytes` (16 MiB),
  `--min-free-bytes` (1 GiB), `--push-reserve` (256 MiB), `--git-memory-limit` (8 GiB, Linux). CPU limit 900 s is a constant. The F2a runner gate
  (`--git-concurrency`) is separate and governs the API's own git calls.
- **Commit authors.** A branch's `commit.author.username`/`committer.username` is the login of the one user whose email
  matches the commit's address, empty if none or ambiguous (recorded K#32, N#5).
- **Departures** (all in `departures.json` with reasons): read-only collaborator pushes are 403 at the advertisement
  (C#30, K#34; Gitea declines in pre-receive), the default-branch delete message (J#62), protocol v2 advertisements have no
  `# service=` preamble (V#5), the unborn-default behaviour above (N). Gitea's behaviour that the tests cannot reproduce
  and sc-forge does not copy: moving HEAD to the first pushed branch.
- **Conformance gate.** `forge-check.sh` replays `A B C J K L M N R V` (10 scenarios). `slice-pending.json` now has
  `{"stop": [N, text], "defer": [[index, "METHOD /path"], ...]}` entries: a deferred exchange still runs and must be the
  recorded call, but its mismatch waits for a later slice, and it fails the run when it starts passing. `B` stops at its
  first contents call; J's `/tags` and `/git/refs/tags`, K's and N's `/contents`, and K's org listing counts (which depend
  on scenarios that need F3/F4 routes) are deferred. `S` needs a PR (F4); `X`, `D`, `E`-`I`, `O`-`Q`, `T`, `U`, `W` stay out.
  A departed git step still has its command line compared; credentialed URLs compare equal under `http` and `https`.
- **Differences from the plan.** Admission takes the per-repository slot first (the plan said global first, which lets a
  flood on one repository hold global slots while waiting); the realm and RPC cache policy are Gitea's (the plan departed
  from both); fetch-by-id of a deleted branch tip works for anyone with read access to that repository, as stated in the
  threat model. Not built: a test that asserts memory is bounded by blocking the child's stdin (the bounded channels are
  the mechanism; the 20 MiB push/clone test exercises the streaming path), per-owner quotas, `gc` of killed pushes' quarantine
  directories (F5).

### F3a decisions (as built)

F3a is the read half of the content API (plan: `docs/superpowers/plans/2026-10-23-p38-f3a-content-reads.md`). The
write half (`POST`/`PUT`/`DELETE` contents) is F3b, below; F3a shipped them as 501 stubs behind the auth checks.

- **Routes.** `git/refs`, `git/refs/{ref..}`, `tags`, `commits`, `git/commits/{sha}` (+ `.diff`/`.patch`),
  `git/trees/{sha..}`, `contents`, `contents/{path..}`, `archive/{name..}` under `/repos/{o}/{r}` (read scope, read
  permission). Only `refs/heads` and `refs/tags` are listed; `refs/forge` and `refs/pull` are never visible.
- **Revisions are a grammar, not git syntax.** `HEAD` is the default branch; a valid branch name is tried as
  `refs/heads/` then `refs/tags/`; 4 to 64 hex digits are an object id. Nothing else reaches git (`:/x`, `main^{/x}`,
  `@{0}`, `--output=`, `HEAD~1` are all 404). Only resolved object ids are passed to later commands.
- **Paths are literals.** `--literal-pathspecs` and `--` on every command that takes one; output is NUL-delimited.
  `..`, NUL and an absolute path are 422 on `commits?path=`; on `contents` a leading `/` is trimmed and the rest is a
  literal lookup (404 when absent).
- **Output caps.** Listings and diffs 64 MiB, a blob read 16 MiB (a larger file answers with `content: null`), 120 s for
  each capped command (the rest use the runner's 30 s). The operator's runner output cap does not apply to these. Over the cap is 413, a timeout 504, a saturated runner 503. All reads run under the repository's read lock.
- **Archives are buffered in RAM**, capped at 128 MiB (413 over); `tar.gz` is built from the tar in the server. At most
  four exist at once (`ArchiveSlot`, a fifth is 503), each until its body is written: `Resp::hold` carries the slot to the
  end of the response. A streamed archive needs a pipe stage and is deferred.
- **`last_commit_sha` in a contents listing** costs one git process per entry, so it is exact for the first 100 entries
  only; later entries carry the commit id that was read. Recorded Gitea does the exact walk for all of them. A symlink
  target is read for the first 100 entries of a listing and only when the link blob is at most 4 KiB.
- **Recorded Gitea quirks reproduced:** a commit's `tree.sha`/`url` carry the commit id; `git/trees/{x}` answers `sha` =
  commit id when a commit or branch is named; a directory's `git_url` uses `git/blobs/<tree id>`; the archive `Link`
  names `.tar.gz?rev=` even for a zip; a tag's `commit.url` uses the tag object id while `sha` is the peeled commit;
  `/tags` is newest first; an empty repository answers `contents` with `200 []` for any path, commits with 409, `git/refs`
  with 404, `git/trees/main` with 400; a contents 404 carries the "GetContentsOrList" message; the commits `Link` header
  is alphabetical over all parameters with the page clamped to the last.
- **Departures.** An unknown ref on `commits` is 404 (E#19; Gitea 1.22.6 answered 500). `commits?not=` is 400 (it
  would otherwise be ignored silently). A file name that is not valid UTF-8 is listed with U+FFFD in place of the bad
  bytes and cannot be fetched by that name; names with a control character are listed but their URL is 404.
  The `.patch` of a merge commit is its diff against the first parent in mailbox form (`format-patch` skips merges).
  A `commits` page may carry at most 50,000 changed files in total (413 over). `submodule_git_url` is always `null`
  (Gitea reads it from `.gitmodules`; not built). A parent's `created` is the child's committer time, as recorded.
- **Empty repositories.** "Empty" is "the default branch does not resolve", as for the `empty` field. An unnamed read of an
  unborn default is the recorded empty answer even when other branches exist (Gitea would have adopted the first pushed
  branch as default, see N#13); a *named* `sha`/`ref` that exists is served, and a named one that does not is 404 unless the
  repository has no branch or tag at all.
- **Not served.** `git/blobs`, `git/tags` and web `raw` URLs appear in response bodies as Gitea writes them but are not
  routes.
- **Conformance gate.** `forge-check.sh` now replays `A B C D E J K L M N R V` (12 scenarios). `E` stops at its first
  contents write (`[42, KeyError: 'sha']`) with E#36 to #41 deferred to F3b; `D` defers its PR listing and `B` its status
  post (F4).

### F3b decisions (as built)

F3b is the write half of the content API (plan: `docs/superpowers/plans/2026-10-24-p38-f3b-contents-writes.md`, with its
"Decisions after independent review"). `gate E` replays E#36 to #43 unchanged.

- **Routes.** `POST`, `PUT` and `DELETE` `/repos/{o}/{r}/contents/{path..}` (write scope, write permission). `DELETE` is
  unrecorded (the recordings only have POST and PUT); it follows the Gitea 1.22 API: `sha` required, `{content: null,
  commit, verification}`.
- **Request.** `content` base64 (required for POST/PUT, an empty string is an empty file), `message` (trailing
  whitespace trimmed, one `\n` added, default `Add|Update|Delete <path>`, NUL refused), `branch` (base, default the
  default branch from the row read under the lock), `new_branch` (empty or equal to `branch` is absent), `sha` (PUT and
  DELETE). `author`, `committer`, `dates` and `signoff` are accepted and ignored (the authenticated user is author and
  committer; departure from Gitea); `from_path` is 422 because ignoring a rename would leave a copy.
- **Path rules** (`gitwrite::write_path_ok`): `valid_path`, no `\`, no trailing `/`, at most 64 components of at most 255
  bytes, no `.git` alias (case, trailing dots and spaces, `:stream`, `git~1`, HFS-ignorable code points) and no
  `.gitmodules` alias: **`.gitmodules` cannot be written through the API** (its URL/path/name checks run only in
  `receive.fsckObjects`). A `.gitattributes` line of 2048 bytes or more is refused, under every NTFS/HFS alias of the name; `.gitmodules` is refused under every alias including the `gitmod~N` and `gi7eba~N` short names. Windows device names, `:` in a name and
  case-fold sibling collisions are not prevented.
- **Semantics.** New files are `100644`; PUT keeps `100755` (and normalises legacy modes such as `100664` in the directories
  it rebuilds; untouched subtrees keep their ids); a symlink, gitlink or directory at the path is 422 for PUT/DELETE, and
  POST on any existing entry or under a non-tree parent is 422. An unborn default branch (`empty: true`, whatever other
  branches exist) takes a POST as its first, parentless commit; PUT/DELETE there and `new_branch` from an unborn base are
  404. `new_branch` must not equal, contain or lie under an existing branch name (422, before any object is written).
  A missing path on PUT/DELETE is 404 (unrecorded; Gitea may answer 500).
- **Locks.** A per-repository write gate (`limits::Gate(1)`, 10 s, 503 when busy) is taken first, then the shared
  lifecycle lock, each once (`Lifecycle::with_write_row`, which hands over the fresh row); documented in
  `lifecycle.rs` as the order F4 must follow. The runner gate applies to every git command.
- **Publication.** Objects first, the ref last by `update-ref` CAS. After any failure the ref is re-read and the outcome
  decided by `gitwrite::classify` (landed, which includes a tip that has our commit as an ancestor, as when a push built on a killed `update-ref` that had succeeded; lost round, lock held with a 50 ms pause, branch gone 404, `new_branch` exists
  422, ref D/F conflict 422, anything else 500, logged); three lost rounds is 409 `the branch was changed concurrently,
  try again`, or 503 `the branch is locked` when every round met a held ref lock (a killed git can leave a stale
  `refs/heads/<b>.lock`; the log then tells the operator to remove it). The response is built before the ref moves and nothing is read from git afterwards; the repository's
  `updated_unix` stamp after a successful write is log-only on failure.
- **Limits.** Body (`--max-body-bytes`, 1 MiB) bounds content; 64 levels, 16 MiB per raw listing and 32 MiB cumulative
  listing per attempt, 60 s for the operation (checked between attempts and between the walk, the rewrite and the commit; one git command may still run up to its own limit), free disk against `--min-free-bytes` through the same reservation pool as
  pushes (content plus 8 MiB, and per attempt the tree bytes it read).
- **Protection seam.** `policy::check_contents_write(target, creating)` is evaluated early (Gitea checks protection first)
  and again immediately before the ref update on every attempt, including for `new_branch`; it permits everything until
  F4 adds rules, in the same module as the pre-receive policy.
- **Identity.** Author and committer are the authenticated user's login and stored email (else
  `<login>@noreply.localhost`); both commit dates are one server timestamp (`GIT_*_DATE`) so the response matches the commit.
- **Not built / not tested.** The 409 exhaustion path has a unit-tested classifier but no end-to-end test (it needs a
  deterministic interfering writer); the F4 `refs/forge/pull/<n>/head` refresh for a contents write to a PR branch;
  portable-name collision rules; a disk reservation sized to the exact rebuilt trees.

### F4b decisions (as built)

F4b adds migration 4 (`pulls`, `mergeability_cache`, `reviews`, `issue_comments`) and gates F, O (the merge-dependent exchanges
stay `defer`red until F4c), P and D#13.

- **PR object.** The recorded 1.22.6 shape (`id` is the row id, `number` the per-repository index; `user` is the creator's full
  account object; `base.repo`/`head.repo` are the repository object). Open PRs show the live tips; `mergeable`, `merge_base`,
  `changed_files`, `additions`, `deletions` come from `merge-base`, `diff-tree --numstat` and `merge-tree --write-tree`, cached
  by `(base_sha, head_sha)`; a closed PR reads `mergeable: true`; a merged PR is frozen (F4c). Create needs write access (Gitea
  lets any reader open one; stricter here); another repository as head is 404 (forks are a non-goal). `head == base` as commits
  is 422 `Invalid PullRequest: There are no changes between the head and the base`; a head contained in base is accepted.
  PATCH answers 201 and takes `title`, `body`, `state` and `base`; the PR's creator or write access may use it.
- **Lists.** `state` open (default), closed (closed and merged) or all; `sort` newest (default), oldest or recentupdate; the
  `head` filter is ignored like Gitea's; 404 on a repository with no commits (D#13). `X-Total-Count` and `Link` follow the
  request's own query (see below).
- **Retention (differs from the F0 text).** No `post-receive` database write and no `freezing` state: refresh and freeze both
  run in the server under the write gate. `pulls::sync_locked` follows every head branch with `refs/forge/pull/<n>/head` and
  closes an open PR whose head branch is gone (keeping the retained head as `final_head_sha`); it runs after an accepted push,
  a contents write, a branch DELETE and at startup, and reads converge by running it when an open PR's head is missing. The
  ref is written before the PR row exists. Branch DELETE retains the tip (under the exclusive lock) before the CAS delete, and
  the `pre-receive` hook records `old` into the ref of an open PR whose head branch a push deletes (no quarantine variables
  in that spawn; any failure refuses the push). `head_gone` marks a PR reopened without its branch so a later sync leaves it
  open (recorded O#26-O#27). The startup reconcile also restores the ref of closed and merged PRs from `final_head_sha` and
  removes `refs/forge/pull/<n>/head` refs with no row.
- **Reviews.** `event` APPROVED/APPROVE, REQUEST_CHANGES, COMMENT, anything else PENDING; approving or requesting changes on
  your own PR is 422; `official` is stored at creation (write access and a deciding state) and a later deciding review by the
  same reviewer marks the earlier one `dismissed` and not official; PENDING reviews are visible only to their author but
  counted in `X-Total-Count` (recorded quirk); the POST answer carries the full reviewer account, reads the nested form.
  Inline review `comments` are refused (422) and a review's comment list is always empty. Issue comments live under
  `/issues/{n}/comments` where `n` is a PR number (`issue` scope), oldest first. Caps: 64 KiB of text, 1000 reviews and 5000
  comments per PR.
- **Links.** All paged lists repeat the request's own query parameters (sorted by name, first value of a repeated one,
  re-encoded strictly), with `page` replaced and clamped to the last page, and `limit` only when the request sent one (recorded
  P#19-P#32). The commits list keeps its always-`limit` form. Branches are listed newest commit first, ties by name (P#19-22).
  The combined status pages from the newest end and lists each page oldest first (P#40-41); history links name the request path.
- **Not built / departures.** Forks, labels, milestones, assignees, requested reviewers and inline review comments; a
  list of up to 50 PRs computes its cache misses one after another.

### F4a decisions (as built)

F4 ships as three PRs (F4a protection and statuses, F4b pulls, reviews and comments, F4c merge and recovery; plan:
`docs/superpowers/plans/2026-10-24-p38-f4-pulls-statuses-merge-protection.md` with its "Decisions after independent
review"). F4a adds migration 3 (`branch_protections`, `commit_statuses`) and gates scenarios H, I, W and the first five
exchanges of Q.

- **Rules.** `/branch_protections` CRUD (admin to write, read to read). A rule names one branch, compared
  case-insensitively like `same_branch_name`; glob names and glob context names are refused (422), as is any setting
  `sc-forge` does not enforce when set to a non-default value (`required_approvals`, whitelists, `block_on_*`,
  `require_signed_commits`, `protected_file_patterns`, the 1.26.2 force-push keys). `enable_status_check` needs a
  non-empty `status_check_contexts` (a gate that requires nothing would fail open). Responses carry the recorded key set;
  a rule created without contexts reports `status_check_contexts: null`, a branch with no rule reports `[]` on the
  branch object. Rule changes run under the write gate, so they are ordered against contents writes.
- **`enable_push` false:** no push (administrators included), no contents write, no deletion; the rule also reserves
  its name, so a push or a contents `new_branch` cannot create the branch (stricter than Gitea, which checks only an
  existing branch). **True:** a fast-forward push and a contents write are allowed (even with required checks unmet,
  W#8); a non-fast-forward push and a deletion are refused for everyone. A merge is not subject to `enable_push`.
- **One policy.** `policy::{check_protected_push, check_contents_write, check_branch_delete}` take the loaded `Rules`;
  the `pre-receive` hook, the contents API (twice per attempt, the second read immediately before `update-ref`, under
  the gate) and the branch DELETE call them. The hook decides fast-forward with `git merge-base --is-ancestor` under the
  runner's sanitized environment plus the quarantine's `GIT_OBJECT_DIRECTORY` and `GIT_ALTERNATE_OBJECT_DIRECTORIES`
  (each must lie under the repository's own `objects/`), the git binary from `FORGE_GIT_BIN`; any doubt refuses.
  A push is not excluded by the gate, so a rule created while a push is in flight can be bypassed by that one push.
- **Branch DELETE** refuses a protected branch (403 `branch <b> is protected and cannot be deleted`) and deletes with
  the observed tip as the expected old id (retrying a few times), so a push that lands between the read and the delete
  is not deleted with it.
- **Statuses.** `POST /statuses/{sha..}` (write; the sha may be a branch, tag, `HEAD` or id, resolved to a commit),
  `GET /statuses/{ref..}` and `GET /commits/{ref}/statuses` (history, newest first, paged), `GET /commits/{ref}/status`
  (latest per context, oldest first, paged; `total_count` is the page, `X-Total-Count` the whole). Unknown state or a
  missing `state` is 422, unknown commit 404 (departures); `context` up to 1024 bytes and not defaulted (recorded H#36),
  `description` up to 1024 characters, `target_url` empty or plain `http(s)`. The combined state is `failure` for any
  `error`/`failure`, else `pending`, `warning`, `success`, `skipped` (only the first three are recorded). A commit with
  no statuses reads `pending` with the real sha and `repository: null`. The creator object shows
  `<login>@noreply.localhost`, never the stored address, and `is_admin: false`. Storage is bounded per commit: 100
  distinct contexts and 100 rows per context (oldest dropped; a departure from Gitea, which keeps everything).
- **Refusal texts.** Pushes are refused with `refusing to update protected branch <b>: direct pushes are not allowed`,
  `refusing to force-push protected branch <b>` and `refusing to delete protected branch <b>` (departure entries for
  I#7, I#8 and I#10; the default branch keeps F2b's wording and is checked first).

## Open questions

1. The merge of a PR whose head is already in base (recorded: 405 `try again later`,
   `changed_files` 0) has no departure entry; sc-forge reproduces it, so the
   fixture applies unchanged.
2. TLS: all known deployments terminate at a proxy or private network. Add
   `tlsio` only if one needs it (it needs a sync-to-hyper adapter).
3. Whether `has_actions` PATCH is accepted and ignored or refused.
4. Signed ref attestation (the THREAT-MODEL's deferred gittuf-shaped item) is out
   of scope; v1 documents the rollback gap.
