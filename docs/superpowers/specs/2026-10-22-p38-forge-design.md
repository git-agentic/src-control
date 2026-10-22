# Design: sc-forge, a Gitea-compatible Git forge (P38)

- **Date:** 2026-10-22
- **Status:** Draft, pre-implementation (ADR-0058 is Proposed)
- **ADR to write at build time:** firm ADR-0058 from Proposed to Accepted when F2 ships
- **Contract source:** `crates/forge/conformance/` (recorded from real Gitea 1.22.6
  and 1.26.2; see "Conformance") and the client survey summarized below

## Goal

A self-hostable Git forge that a platform can swap in for Gitea by changing a
base URL and a token. It serves bare Git repositories over smart HTTP and the
subset of Gitea's `/api/v1` that two real clients use: an agent runtime that
opens, gates and merges pull requests, and a portal that provisions repos,
users and tokens and brokers Git traffic.

Success is behavioural: the same clients, unmodified, pass their own end-to-end
flows against `sc-forge`. Wire compatibility is the means, not the product.

## Non-goals (and why)

- **A web UI.** The clients are programs. Humans use their own Git tooling and
  the portal.
- **Actions/CI, webhooks, issues, wiki, packages, LFS, OAuth apps.** No client
  calls them. Commit statuses are posted by the client's own suite runner;
  protection can require named status contexts.
- **SSH transport (v1).** No client uses it: the portal's URL policy forbids
  `ssh://` and the agent runtime authenticates over HTTP only. Follow-on:
  OpenSSH with `AuthorizedKeysCommand` calling `sc-forge`, not an in-process SSH
  server. `user/keys` is cut with it.
- **Squash and rebase merge, forks.** Every merge request seen sends
  `Do: "merge"`; there is no UI where a human picks a style. `Do` values other
  than `merge` answer 422 until a client needs them. Pull requests are same
  repository only.
- **Required approvals in branch protection.** Clients read reviews and decide
  client-side; nothing reads server-side approval rules. Protection supports
  `enable_push` and `status_check_contexts` only.
- **High availability.** One writer process, one data disk, snapshot backup.
- **Storing `.sc/` repos.** Hosted repos are bare Git (ADR-0058, decision 1).
  They get none of secrets, per-file encryption or private branches.
- **Changing Gitea's behaviour for the better.** Where a client matches on a
  Gitea quirk (error text, status codes, "try again later"), `sc-forge`
  reproduces it. Improvements are made after the clients are migrated.

## What the clients need

Tiers decide build order. Each row is a route plus the response keys a client
actually reads; full keys, status codes and message texts live in the recorded
fixtures, not here.

**Tier 1, the default delivery path**
- `GET /api/v1/version`, `GET /api/healthz` (container health).
- `GET /api/v1/user`; `GET /api/v1/users/{u}`.
- `POST /api/v1/admin/users`, `PATCH /api/v1/admin/users/{u}` (password reset,
  visibility); duplicate create answers 422.
- `POST /api/v1/orgs`, `GET /api/v1/orgs/{o}`,
  `GET /api/v1/users/{u}/orgs/{o}/permissions` (`can_create_repository`).
- `POST|GET|DELETE /api/v1/users/{u}/tokens` under HTTP Basic (password): the
  mint response carries `sha1`; list carries `id`, `name`, `token_last_eight`.
  The admin token is not accepted on these routes.
- `POST /api/v1/orgs/{o}/repos` (`name`, `description`, `private`,
  `default_branch`, `auto_init`, `readme`); duplicate answers 409 or 422 with
  "already exists".
- `GET|PATCH|DELETE /api/v1/repos/{o}/{r}`; keys read: `full_name`, `name`,
  `empty`, `private`, `description`, `default_branch`, `permissions`.
- `PUT|DELETE /api/v1/repos/{o}/{r}/collaborators/{u}` (204).
- `GET /api/v1/repos/{o}/{r}/branches/{b}` (`commit.id`).
- Git smart HTTP at `/{o}/{r}.git` (see "Git transport").

**Tier 2, pull requests and gating**
- `POST|GET /pulls`, `GET|PATCH /pulls/{n}`; the full PR object comes back from
  create (`number`, `state`, `merged`, `merge_commit_sha`, `changed_files`,
  `mergeable`, `head.{ref,sha,repo.full_name}`, `base.{ref,sha,repo.full_name}`,
  `html_url`). `GET /pulls?state=all&head=…&limit=50` must work; clients filter
  by `head.ref` themselves because stock Gitea ignores `head`.
- `POST /pulls/{n}/merge` with `{"Do":"merge","head_commit_id":…}`.
- `GET|POST /pulls/{n}/reviews`, `GET /pulls/{n}/reviews/{id}/comments`,
  `GET /issues/{n}/comments`.
- `POST /statuses/{sha}`; `GET /commits/{sha}/status` (combined) and
  `GET /statuses/{sha}` (history).

**Tier 3, content reads (import and portal)**
- `GET /repos/search`, `GET /branches`, `GET /git/refs/heads[/{b}]` (an array),
  `GET /commits` (`X-Total-Count`, paging), `GET /git/commits/{sha}` (+`.diff`),
  `GET /git/trees/{sha}?recursive=true`, `GET|POST|PUT /contents/{path}`,
  `GET /archive/{ref}.zip`.

**Tier 4, protection**
- `POST|GET|PATCH|DELETE /branch_protections` with `branch_name`,
  `enable_push`, `enable_status_check`, `status_check_contexts`; a merge that
  lacks a required context is refused with a message containing
  "required status checks".

**Client behaviours that are part of the contract**
- Auth is `Authorization: token T`. Git uses HTTP Basic with the token as the
  password under any username, including `oauth2`. A client re-resolves its token
  once on 401 and replays, including POST.
- A foreign token on a private repo must answer what Gitea answers (the
  fixtures decide 401 versus 404); one flow asserts it.
- Merge outcomes are classified by case-insensitive substring of the body:
  "conflict" with 405 or 409, "try again later" with 405 (with
  `changed_files == 0` meaning nothing to merge). A 2xx merge answer is not
  trusted; the client re-reads the PR for `merged` and `merge_commit_sha`.
- A PR is "landed" if its frozen head is an ancestor of trunk, or the merge
  commit has one parent and the tree comparison matches (squash). A real merge
  commit satisfies the first rule.
- Combined status must list only the latest status per context; clients do not
  deduplicate. `X-Total-Count` must equal the listed count.
- `GET /commits` on an empty repo answers 409.
- Git needs `uploadpack.allowReachableSHA1InWant`, `uploadpack.allowFilter`,
  shallow fetch, `Git-Protocol: version=2`, and
  `push --force-with-lease=refs/heads/b:` semantics.
- Bootstrap shells into the container: `admin user create --admin
  --must-change-password=false`, `admin user change-password`, and
  `admin user generate-access-token --scopes all --raw`. `sc-forge` accepts the
  same subcommands and flags so those scripts need only a binary name change.

## Architecture

### Crate and dependency rule

New top-level adapter `crates/forge` (package `scl-forge`, binary `sc-forge`).
It is a sibling of `cli` and `desktop`, not a consumer of `repo`: hosted repos
are plain Git, so `scl-repo` is not linked. Dependencies: `scl-core` only if a
helper is shared (BLAKE3 token hashing, `atomic_write_durable`); `scl-tlsio` is
linked only when TLS is added (deferred). **`gix` stays quarantined in
`gitio`; the forge does not use it.** All Git access is the system `git`
binary, spawned with argument arrays (never a shell), as the P18 bridge already
does. `CLAUDE.md`'s dependency rule gains one sentence in the F1 PR.

New direct dependencies, each named here so review sees them:

| Dependency | Why |
|---|---|
| `hyper` 1.x + `hyper-util` + `tokio` (multi-thread rt, net, process, io-util) | Routes with JSON, queries and streamed pack bodies; `hyper` and `tokio` are already in the lockfile through `objio`'s S3 SDK. Confined to `scl-forge`. |
| `rusqlite` (`bundled`) | Metadata. Relational queries (PR lists, status latest-per-context, collaborator joins), transactions and migrations; flat files would reimplement a database badly. First SQLite use in the workspace. |
| a password hash (`argon2`) | Basic-auth password verification for token routes. |

### Storage layout (`--data-dir`)

```
<data>/forge.db            SQLite, WAL, one writer connection + readers
<data>/repos/<o>/<r>.git   bare repositories (lower-cased canonical names)
<data>/hooks/              hook shims, selected with -c core.hooksPath
<data>/tmp/                scratch for index files and archives
```

The data disk is the unit of backup (disk snapshot), as with Gitea. No secret
lives outside it.

### Metadata (SQLite)

`users` (login, lower_login, kind user|org, email, password hash, is_admin,
visibility), `org_members` (org, user, owner|member), `tokens` (user, name,
BLAKE3 hash of the raw token, last_eight, scopes, expires_at, created_at),
`repos` (owner, name, lower_name, private, description, default_branch),
`collaborators` (repo, user, read|write|admin), `pulls` (repo, number,
head_ref, base_ref, title, body, state, merged, merge_commit_sha, head_sha at
merge, changed_files, timestamps), `reviews`, `comments`, `commit_statuses`
(repo, sha, context, state, description, target_url, created), `branch_protections`
(repo, branch, enable_push, status_check_contexts JSON). Per-repo `index`
counter for PR and comment numbers. Schema migrations are numbered SQL applied
at startup under a version table; a newer schema than the binary refuses to
start.

### Auth and authorization

- Tokens are 40 hex characters (the length Gitea issues; clients treat them as
  opaque). Stored as BLAKE3 hashes, compared in constant time, optional expiry.
  The token-store primitives follow ADR-0040's (`sct-` format excepted);
  `serve_tokens.rs` is single-repo and file-backed, so only the ideas carry over.
- Accepted credentials: `Authorization: token T`, `Bearer T`, Basic with the
  token as password (any username), and Basic with a user's password on the
  token routes only. Password attempts are rate-limited per login.
- Scopes: `all`, `read|write:{repository,user,organization,admin,issue}`;
  `public-only` is accepted and ignored (all repos are private by
  configuration). Every route declares the scope category and level it needs.
- Repository access = site admin, org owner, repo owner, or a collaborator
  grant (read < write < admin). Org membership alone grants nothing
  (`FORCE_PRIVATE` semantics). A token is intersected with its user's access.
  There are no teams.
- Authorization failures answer what the recorded Gitea answers (401, 403 or 404
  per route), not a uniform choice.

### Git transport

Routes: `GET /{o}/{r}.git/info/refs?service=git-upload-pack|git-receive-pack`,
`POST /{o}/{r}.git/git-upload-pack`, `POST /{o}/{r}.git/git-receive-pack`.

- The server authenticates and authorizes first (read for upload-pack, write for
  receive-pack), then spawns `git upload-pack --stateless-rpc` or
  `git receive-pack --stateless-rpc` directly, no CGI. Request body streams to
  stdin and stdout streams back. `Git-Protocol` maps to `GIT_PROTOCOL` when it
  matches `version=[0-9]+(:…)?`.
- Spawn flags: `-c uploadpack.allowFilter=true -c
  uploadpack.allowReachableSHA1InWant=true -c receive.fsckObjects=true -c
  receive.maxInputSize=<limit> -c core.hooksPath=<data>/hooks`. Hooks are never
  read from a repository, so a pushed `hooks/` cannot run.
- Unauthenticated access to a private repo answers 401 with
  `WWW-Authenticate: Basic`, so git prompts and retries.
- A `pre-receive` shim (`sc-forge hook pre-receive`, environment carries repo and
  user ids) enforces branch protection (`enable_push: false` rejects any update
  to the branch from receive-pack) and refuses deleting the default branch. The
  merge path does not go through receive-pack, so protection does not block
  server-side merges.
- A per-repository write lock serializes ref updates made by the server itself
  (merges, content commits). Pushes rely on Git's own ref locking.

### Server-side Git operations

All plumbing, no working tree, all against the bare repo. Minimum `git` 2.40
(`merge-tree --write-tree`), shared with the clients' own requirement.

- **Reads:** `for-each-ref`, `rev-parse`, `log` and `rev-list` with a fixed
  format, `cat-file`, `ls-tree -r`, `diff-tree`/`diff`, `archive --format=zip`.
- **Contents write:** temp `GIT_INDEX_FILE` (`read-tree`, `update-index
  --cacheinfo`, `write-tree`), `commit-tree`, then `update-ref <ref> <new> <old>`
  as a compare-and-swap. A stale `sha` in a PUT fails like Gitea.
- **Merge (`Do: merge`):** under the repo lock, re-read base and head tips;
  refuse if `head_commit_id` is present and differs from the head tip; run
  `git merge-tree --write-tree base head`; on conflict answer as Gitea does; on a
  head that is an ancestor of base answer Gitea's "nothing to merge" form; else
  `commit-tree -p base -p head` with a Gitea-style message and the merging user
  as author and committer, then `update-ref base new old`. The answer is
  synchronous: the PR reads `merged: true` as soon as the call returns, so the
  clients' re-read always sees the transition.
- **Mergeability** (`mergeable` on the PR object) is computed on read with
  `merge-tree`, not cached.
- **Argument hygiene:** ref names and repo names validated by allowlist before
  use; every spawned command separates options from operands with `--`; owner and
  repo path components come from database lookups, never from the URL string.

### HTTP surface rules

- JSON errors in Gitea's shape `{"message": "...", "url": "<base>/api/swagger"}`
  with the status and message texts the fixtures pin.
- Pagination: `page` and `limit` (cap 50, default 30), `X-Total-Count`, and a
  `Link` header where Gitea sends one. Routes Gitea does not paginate do not
  paginate here.
- Request limits: JSON body cap, a header cap, a git request cap
  (`--max-pack-size`, reusing ADR-0041's vocabulary), an idle timeout, a global
  connection cap, and a per-git-process wall-clock limit.
- `GET /api/v1/version` answers a Gitea-compatible version string plus a
  `sc-forge` build suffix; clients only use the route as a health probe.

### CLI

```
sc-forge serve --data-dir DIR --listen ADDR --public-url URL [limits…]
sc-forge admin user create --username U --password P --email E [--admin] [--must-change-password=false]
sc-forge admin user change-password --username U --password P [--must-change-password=false]
sc-forge admin user generate-access-token --username U [--token-name N] [--scopes S,…] [--raw]
sc-forge admin org create --name O --owner U
sc-forge hook pre-receive          # internal
```

`admin` operates on the data dir directly (SQLite locking makes it safe while
`serve` runs); it needs no network.

## Phases

| # | Slice | Done when |
|---|---|---|
| F0 | Contract | Recorder harness plus fixtures from Gitea 1.22.6 and 1.26.2 (`crates/forge/conformance/`), this spec, ADR-0058 Proposed, reviewed. |
| F1 | Skeleton, auth, bootstrap CLI | `serve` boots; migrations; users, orgs, tokens (Basic mint/list/delete), scopes, `/version`, `/healthz`, `/user`, `/users/{u}`, admin user create/patch, permissions; `admin …` CLI parity. Tier-1 non-repo fixtures pass `check`. |
| F2 | Repos and Git transport | Repo create/get/patch/search/delete, collaborators, `branches/{b}`, smart HTTP with ACL and pre-receive hook. Real `git` clone, push, fetch-by-sha, partial clone, shallow, `--force-with-lease`; 401 and foreign-token behaviour match fixtures. The multi-tenant threat-model pass is done before this merges. |
| F3 | Content API | Branches, refs, commits, git commits/trees/diff, contents GET/POST/PUT, archive zip. |
| F4 | PRs, statuses, merge, protection | Pulls, reviews, comments, merge (stale-head guard, conflict, empty, protection refusals), statuses with latest-per-context, branch protection. |
| F5 | Ops | Container image (git 2.40+, no sshd), limits, structured logs, `--data-dir` backup note, optional TLS decision. |
| F6 | Conformance on the first deployment | The consumers' own end-to-end flows run with only the Project Git host swapped. src-control's exit gate. |

## Conformance

`crates/forge/conformance/run.py` has two modes. `record` drives real Gitea
through scenarios and writes normalized fixtures (status, selected headers,
body, placeholders for shas, timestamps, ids and hosts). `check` replays the same
scenarios against any server and compares: status exactly, recorded headers,
every recorded JSON key present with the same JSON type (extra keys allowed),
and message texts by the distinctive substrings the scenario lists.

The recorded fixtures are the contract. Where fixtures from the two Gitea
versions differ, the spec names the version `sc-forge` follows (the older
pinned compose version, 1.22.6, unless a client needs the newer behaviour).
Fixtures replace the clients' hand-authored transcripts, several of which are
labelled "authored, not recorded". F6 is the acceptance run, not the regression
suite: CI runs `check` plus end-to-end tests that drive `sc-forge` with real
`git`.

## Threat model (to complete before F2 merges)

Hosting other people's repositories is the first time this project accepts
untrusted writers over a network, which `docs/THREAT-MODEL.md` names as a
revisit trigger for signed ref attestation. The F2 gate covers:

- Token handling: hashing, constant-time compare, expiry, scope enforcement
  matrix per route, per-login rate limit on passwords, token and password
  redaction in logs.
- Tenant isolation: repo path derivation, ref and path validation, argument
  injection into `git`, symlink and `..` handling in contents and archive.
- Resource abuse: pack size, object count, decompression, concurrent processes,
  slow clients, giant trees.
- Hook confinement: `core.hooksPath` pinned, no repo-supplied hooks, no
  `core.fsmonitor`/`core.sshCommand`/`protocol` config reachable from a pushed
  repo.
- Ref rollback and force pushes: the existing deferred gittuf-style signed ref
  attestation is out of scope here; v1 documents the gap.
- Data integrity: SQLite and repo directory consistency after a crash (repo
  create and delete are two-phase with a startup reconciler).

## Open questions

1. Foreign-token status (401 or 404) and the exact merge texts are decided by the
   recorded fixtures, not here.
2. TLS: all known deployments terminate at a proxy or private network. Add
   `tlsio` only if a deployment needs it; it needs a sync-to-hyper adapter.
3. Which Gitea version string `/version` reports.
4. Whether `has_actions` PATCH is accepted and ignored or refused.
