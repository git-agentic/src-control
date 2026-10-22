# ADR-0058: sc-forge, a Gitea-compatible Git forge

- **Status:** Proposed
- **Date:** 2026-10-22
- **Phase:** 38
- **Builds on:** ADR-0028 (hosted Git through system `git`), ADR-0040 (bearer
  tokens, hashed at rest), ADR-0041 (listener limits), ADR-0042 (TLS stays in
  `tlsio`)
- **Spec:** `docs/superpowers/specs/2026-10-22-p38-forge-design.md`

## Context

A platform that uses Gitea as its project Git host wants to stop operating Gitea.
Its clients are programs: an agent runtime that opens, gates and merges pull
requests, and a portal that provisions repos, users and tokens and proxies Git
traffic. A survey of both found a much smaller surface than Gitea's: about 40
REST routes, Git smart HTTP, and two admin CLI commands that bootstrap scripts
shell into the container for. No client uses SSH, webhooks, Actions from the
host, issues, wiki, LFS or a web UI.

src-control already ships hosted-Git bridging, bearer tokens and listener
limits, but no forge. It does not host Git repos for others, and
`docs/THREAT-MODEL.md` names the first hosted deployment as a revisit trigger.

## Decision

1. **Hosted repos are bare Git.** The forge serves them by running
   `git http-backend` as a CGI per request, after its own authentication and
   authorization (write access sets `REMOTE_USER`, without which receive-pack
   answers 403). `gix` has no server side, and the P18 bridge already depends on
   system `git`. Using `http-backend` keeps the advertisement framing, content
   types, gzip request handling and protocol v2 in Git's hands. The `.sc/`
   alternative is rejected for now: P9 export fails closed on encrypted content
   and private branches are refused at the Git bridge, so `.sc/` repos behind a
   Git face would carry the cost of both models without delivering either's
   guarantees. Consequence, stated plainly: **hosted project repos get none of
   src-control's committed secrets, per-file encryption or private branches.**
   Revisit when an sc-native transport exists for the agent runtime.
2. **The API is a Gitea-compatible subset, not a new API.** Clients then switch
   by base URL and token. The contract is recorded from real Gitea 1.22.6 and
   1.26.2 by a scenario harness (`crates/forge/conformance/`) rather than taken
   from the clients' hand-written transcripts, several of which are marked
   authored, not recorded. Where a client depends on a Gitea quirk (error
   texts, status codes, merge outcome strings), the forge reproduces it.
3. **Scope is what clients call.** No Actions, webhooks, issues, wiki, LFS,
   OAuth apps or UI. Commit statuses are posted by the client's own runner;
   branch protection supports `enable_push`, `enable_status_check` and
   `status_check_contexts` only.
   No SSH in v1 (follow-on: OpenSSH `AuthorizedKeysCommand`). No squash or
   rebase merge: every client sends `Do: merge` and no UI exists for a human to
   choose; other values answer 422. Same-repo pull requests only.
4. **New top-level adapter `crates/forge` (package `scl-forge`, binary
   `sc-forge`) linking `{crypto, core}` only.** It does not link `scl-repo`,
   `vfs` or `gitio`. Password hashing (`argon2`), token generation and the
   constant-time compare are added to `crates/crypto` so RustCrypto stays
   quarantined there. `gix` is not used; rustls stays in `tlsio` and TLS is
   deferred (known deployments terminate at a proxy). `CLAUDE.md`'s dependency
   rule gains `forge → {crypto, core}` in the first code PR. The crate is
   unix-only behind a stub `main`.
5. **Metadata is SQLite on the data disk** (`rusqlite`, bundled, WAL, numbered
   migrations): PR lists, latest-status-per-context and collaborator joins are
   relational and need transactions. One writer process; the disk snapshot is
   the backup, as with Gitea today.
6. **Runtime is a `hyper` (HTTP/1) server on a multi-thread `tokio` runtime,
   confined to `scl-forge`.** Both crates are already in the lockfile through
   `objio`'s S3 SDK (which uses only tokio's `rt`); this adds the server and the
   multi-thread runtime to one crate. Hand-rolling HTTP parsing for streamed
   pack bodies and 40 routes was rejected. `sc serve --http`'s thread-per-connection
   server is unchanged.
7. **Merge is synchronous and server-side, in the bare repo, by plumbing, on
   captured object ids.** Required status contexts are checked against the head
   id, `git merge-tree --write-tree` (exit code 1 means conflict) and
   `commit-tree` build a two-parent merge commit, and one `update-ref --stdin`
   transaction with `verify <head> <head_oid>` and `update <base> <new> <old>`
   publishes it, so "the head I checked is the head I merged" is atomic. A
   `merge_intents` journal row written before the ref update makes the
   Git/SQLite gap recoverable: startup and retries finalize or abort from the ref
   state. A merge through a PR is always allowed onto a protected branch; direct updates
   follow the rule's `enable_push` (required status contexts gate merges only). This gives
   clients a real merge commit (the ancestry rule of their landing check) and
   `merged: true` on the next read.
7a. **Protection is one policy for every mutation path.** Receive-pack
   (pre-receive), contents writes and merges share one function; client pushes
   are limited to `refs/heads/*` and `refs/tags/*` (so `refs/replace/*` and
   server refs cannot be written), every Git spawn runs with
   `GIT_NO_REPLACE_OBJECTS=1`, a scrubbed environment and a pinned
   `core.hooksPath`, and the server keeps `refs/forge/pull/<n>/head` so
   unmerged PR commits survive branch deletion and gc.
7b. **Credentials are strictly separated by route.** Token routes accept a
   user's password only (never a token) and only for that user (or a site admin
   authenticating with their own password, which Gitea allows); every other
   route accepts a token only (a Basic password is never tried as a password).
   Scopes cannot be raised by a token; `public-only` tokens are accepted and denied every (private) repo.
   Repo identity on disk is an immutable id, so delete-and-recreate cannot alias
   a running process.
8. **Token format and storage.** Tokens are 40 hex characters (the length
   Gitea issues), stored as BLAKE3 hashes, compared in constant time, with
   optional expiry and scopes (`all`, `public-only`, `read|write:{repository,user,
   organization,admin,issue}`). Basic auth with a password is accepted on the
   token-management routes only; git and the API accept a token as the Basic
   password under any username. Repo access is site admin, org owner, repo
   owner or a collaborator grant; organization membership alone grants nothing.
9. **Bootstrap parity.** `sc-forge admin user create|change-password|
   generate-access-token` accept Gitea's flags (`--admin`,
   `--must-change-password=false`, `--scopes`, `--raw`) so existing bootstrap
   scripts change a binary name, not their logic.

## Consequences

- src-control grows a network service that accepts untrusted writers. The
  multi-tenant threat-model pass (token scopes, repo ACL, argument injection
  into `git`, resource abuse, hook confinement) is a gate on F2 merging, and
  the deferred signed-ref-attestation gap is documented, not closed.
- The crate is pre-1.0 and unaudited. Hosting customer repositories is an
  operator decision made against that fact.
- A new SQLite dependency enters the workspace; `hyper` and `tokio` become
  direct dependencies of one crate.
- Compatibility is a moving target. The recorded fixtures are pinned in the
  repo and `check` runs in CI, so drift shows as a failing test, not a client
  incident. Gitea behaviours the clients do not exercise are not promised.
- Recording from two Gitea versions will expose differences; the forge follows
  the older pinned version unless a client requires the newer.
- The threat-model pass runs twice: with F2 (authentication, tenancy, transport,
  resources) and with F4 (server-side writes, merge races, contents bypass).
- Phase F6 is an acceptance run against the first deployment's own end-to-end
  flows. It is src-control's exit gate but cannot run from this repository's CI;
  the fixtures and `check` are the regression suite.

## Rejected alternatives

- **`.sc/` repos behind a Git bridge:** see decision 1.
- **Keep running Gitea:** the operating cost and its Actions, UI and SSH surface
  are the problem; the used surface is small.
- **A new REST API with a portal provider from day one:** the clients are
  already written against Gitea; compatibility is the cheap way to ship, and a
  native provider can follow once the forge exists.
- **In-process SSH server (`russh`):** large dependency for a transport nobody
  uses.
- **Re-implementing upload-pack and receive-pack:** `gix` has no server side;
  the pack negotiation and `--stateless-rpc` behaviour are exactly what system
  `git` already provides.

## Open

Whether `has_actions` PATCH is accepted or refused, the `/version` string, and
an eventual TLS option are decided during F1 and F5. Foreign-token codes, merge
message texts and the deliberate departures from Gitea are recorded in the spec
("Contract decisions from the recordings") and `crates/forge/conformance/`.
