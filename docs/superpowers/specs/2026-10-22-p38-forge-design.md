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
- `POST /api/v1/orgs/{o}/repos`; duplicate 409 or 422 "already exists".
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
  `GET /issues/{n}/comments`.
- `POST /statuses/{sha}`; `GET /commits/{sha}/status` (combined) and
  `GET /statuses/{sha}`.

**Tier 3, content reads and writes**
- `GET /repos/search`, `/branches`, `/git/refs/heads[/{b}]` (an array),
  `/commits` (`X-Total-Count`, paging), `/git/commits/{sha}` (+`.diff`),
  `/git/trees/{sha}?recursive=true`, `GET|POST|PUT /contents/{path}`,
  `GET /archive/{ref}.zip`.

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
- Git needs reachable-SHA fetch, `blob:none` filters, shallow fetch,
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
`forge → {crypto, core}`. The crate is `#![cfg(unix)]` with a stub `main` so the
Windows workspace check still compiles.

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
owner, private, description, default_branch, state live|deleting),
`collaborators`, `pulls` (repo, number, head_ref, base_ref, title, body, state,
merged, merge_commit_sha, `head_sha_at_merge`, `changed_files_at_merge`,
timestamps), `merge_intents`, `reviews`, `comments`, `commit_statuses` (repo,
sha, context, state, description, target_url, id AUTOINCREMENT),
`branch_protections` (repo, branch, enable_push, enable_status_check,
status_check_contexts JSON), `mergeability_cache` (repo, base_sha, head_sha →
mergeable, changed_files), a per-repo index counter. Numbered SQL migrations run
at `serve` startup only; `admin` commands refuse when the schema differs from
their binary's, and `serve` never caches users or tokens across requests.

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
  `--trusted-proxy-header` names it.

### Git transport

Routes: `GET /{o}/{r}.git/info/refs?service=…`, `POST …/git-upload-pack`,
`POST …/git-receive-pack`. The server authenticates and authorizes (read for
upload-pack, write for receive-pack), resolves the repo id from the database, and
runs **`git http-backend`** as a CGI with `GIT_PROJECT_ROOT=<data>/repos/<id>.git`
and `PATH_INFO` set to the service suffix. This keeps Git's own advertisement
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
  `uploadpack.allowReachableSHA1InWant=true`, `uploadpackfilter.allow=false` with
  an explicit allow for `blob:none` only, `receive.fsckObjects=true`,
  `receive.maxInputSize`, `receive.autogc=false`, `gc.auto=0`,
  `core.useReplaceRefs=false`. Only the `pre-receive` and `post-receive` hook
  shims exist; the hook child receives only `FORGE_REPO_ID`, `FORGE_USER_ID`,
  `FORGE_GENERATION`, `FORGE_DB` and git's quarantine variables.
- **Ref namespace policy** (pre-receive): client pushes may write `refs/heads/*`
  and `refs/tags/*` only. `refs/replace/*`, `refs/forge/*`, `refs/pull/*`,
  `refs/notes/*` and anything else are refused. `refs/forge/` is hidden from
  advertisement (`uploadpack.hideRefs`).
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
- **Policy linearization:** authorization and protection are evaluated once when
  a request starts (the hook re-reads protection at ref-update time under one
  read transaction). A revocation or a new rule affects requests that start after
  it commits; an in-flight push is not cancelled. Documented, not coordinated.
- **PR retention:** the server keeps `refs/forge/pull/<n>/head` for every PR,
  set at creation and refreshed by `post-receive` when the head branch moves,
  and the pre-receive hook records the head into that ref before allowing a
  deletion of a head branch. With `gc.auto=0`, no unreachable PR commit is
  pruned; maintenance gc (F5) runs with a long `--prune` window under the repo
  lock.
- **Admission control** before any git process: global and per-repo limits on
  concurrent git children, per-process wall-clock timeout, per-process
  `RLIMIT_CPU`/`RLIMIT_FSIZE`, a free-space reserve checked before accepting a
  push, and a per-owner byte quota (default off). `receive.maxInputSize` bounds
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
  format, `cat-file`, `ls-tree -r -z`, `diff-tree`, `archive --format=zip`.
- **Contents write** (POST/PUT): validate the path (reject empty, `.`, `..`,
  `.git` and its NTFS/HFS aliases, absolute paths; mode 100644 only), `hash-object
  -w`, a temp `GIT_INDEX_FILE` (`read-tree`, `update-index --cacheinfo`,
  `write-tree`), `commit-tree`, then `update-ref <ref> <new> <old>` (zero old id
  for an unborn branch). The branch must pass the protection policy first. A
  lost CAS rebuilds from the new tip, revalidates the supplied blob `sha`, and
  retries up to 3 times, then answers 409. Server-made commits bypass
  `receive.fsckObjects`, so the path rules above are the check.
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
   `head_sha_at_merge`, `changed_files_at_merge`) in one SQLite transaction; return
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
closed PR keeps its last head through `refs/forge/pull/<n>/head`. Pushing the
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
answers 404 (both versions answer 500: an internal error is not a contract); the
combined status of an unknown sha is `200` with empty fields (1.22.6; 1.26.2
answers 404); a repo with no statuses answers `state: ""` as 1.22.6 does.

### Repository lifecycle

- **Create:** insert the row (`state=creating`), create the directory
  (`git init --bare` with the sanitized environment, `HEAD` symbolic to
  `refs/heads/<default_branch>`), optionally the initial commit (`auto_init`),
  then mark live. A startup reconciler removes directories with no live row and
  completes or removes `creating` rows.
- **Delete:** mark `deleting` (new work for that id is rejected), terminate the
  repo's registered children, rename the directory into `trash/`, delete the row,
  then remove the trash. Hooks verify `FORGE_GENERATION` against the database so
  a straggler fails closed.
- **Default branch:** PATCH updates the row and bare `HEAD` together; the
  reconciler repairs a mismatch. A repo is `empty` when `HEAD` does not resolve
  (computed live). Names: lower-case uniqueness enforced by a database index;
  reserved names (`api`, `admin`, `assets`, `user`, `login`, and the rest of
  Gitea's list), leading `-` or `.`, a trailing `.git`, and anything outside
  `[A-Za-z0-9._-]` are rejected.

### HTTP surface rules

- JSON errors in Gitea's shape `{"message": "...", "url": "<base>/api/swagger"}`
  with the recorded statuses and texts.
- Pagination: `page`, `limit` (cap 50), `X-Total-Count`, `Link` where Gitea
  sends one; ordering is pinned per route from the fixtures. Routes Gitea does
  not paginate do not paginate here.
- Limits: JSON body cap, header cap, idle timeout, global connection cap, git
  request caps (inflated size included).
- `GET /api/v1/version` answers a Gitea-compatible version plus a `sc-forge`
  suffix; clients use the route as a health probe.

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
backup (it omits WAL contents). `synchronous=FULL` and Git's default fsync are
kept. A restore test (kill -9 loop during pushes and merges, then reconcile and
compare) ships with F4.

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
  answers 422 (Gitea silently keeps the old one). Reserved names are the union of
  both versions' lists plus `api`.
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

## Open questions

1. The merge of a PR whose head is already in base (recorded: 405 `try again later`,
   `changed_files` 0) has no departure entry; sc-forge reproduces it, so the
   fixture applies unchanged.
2. TLS: all known deployments terminate at a proxy or private network. Add
   `tlsio` only if one needs it (it needs a sync-to-hyper adapter).
3. Which Gitea version string `/version` reports; whether `has_actions` PATCH is
   accepted and ignored or refused.
4. Signed ref attestation (the THREAT-MODEL's deferred gittuf-shaped item) is out
   of scope; v1 documents the rollback gap.
