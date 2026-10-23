# P38 F3a: refs, tags, commits, trees, contents reads, archive (plan)

F3 is split like F2: **F3a** (this plan) is every read route; **F3b** is the contents write path (POST/PUT/DELETE
`contents`, the CAS ref update, path rules, the protection hook point). Writes touch data integrity and get their own
plan, review and PR. Spec: "Server-side Git operations". Shapes are the recorded ones in
`crates/forge/conformance/fixtures/1.22.6` (E mainly, D for the empty repository, J and S for tags and refs).

## Routes (all `Actor::Repo(Read)`, scope `read:repository`)

| Route | Recorded in | Notes |
|---|---|---|
| `GET /repos/{o}/{r}/git/refs`, `git/refs/{heads\|tags}[/{name}]` | D, E, J | list of `{ref, url, object{type,sha,url}}`; a missing exact ref is 404 `The target couldn't be found.`; an empty repo 404 on the list |
| `GET /tags` | D, J | tag objects (name, message, id, commit, zipball/tarball urls); `X-Total-Count`, paging |
| `GET /commits` (`sha`, `path`, `stat`, `files`, `verification`, `not`, paging) | D, E | `X-Total-Count`, 409 `Git Repository is empty.` for an empty repo, 500 `object does not exist [id: nope, rel_path: ]` for an unknown ref (recorded) |
| `GET /git/commits/{sha}`, `.diff`, `.patch` | D, E | `files`/`stats` filled, `verification` object; `.diff`/`.patch` are `text/plain` git output |
| `GET /git/trees/{sha}` (`recursive`, `per_page`, `page`) | D, E | `X-Total-Count`, `truncated`, `total_count`; 400 `sha not found [main]` when empty |
| `GET /contents`, `/contents/{path}` (`ref`) | D, E, K, N | dir list, file (base64), submodule/symlink variants; `last_commit_sha`; 404 `GetContentsOrList` |
| `GET /archive/{ref}.{zip,tar.gz}` | D, E | `application/octet-stream`, `Link: <...>; rel="immutable"`, 404 `unrecognized repository reference: x` |

Not in F3a: `git/blobs`, `raw`, `commits/{sha}/status` (F4), `pulls/*`, branch protection.

## Design

- One module `gitrefs.rs`-style layer on top of `gitread.rs` (F2a): every client string (ref, sha, path) is resolved once
  to a full object id with `rev-parse --verify --end-of-options <rev>^{commit}`; only ids reach other commands;
  `--end-of-options` before revisions, `--` before paths; paths are literals, output is NUL-delimited and size-capped
  (`Spec` already caps output; archive and diff get explicit larger caps with `OutputTooLarge` -> 413/500 as recorded).
- Every read runs under `Lifecycle::with_read`; a busy runner is 503 (existing `life_err` mapping).
- Ref names in routes use the F2a tail-capture and `refname::valid_branch`; tag names get the analogous check. Refs under
  `refs/forge/` and anything outside `refs/heads|tags` are never listed (same namespace rule as the transport).
- Commit `author`/`committer` user objects: the login resolved by email (`store::login_by_email`, Unicode folded) rendered
  with `user_json`, `null` when none (recorded `author: null` in E).
- Contents `last_commit_sha`: one capped `git log --name-only` pass over the directory, first commit that touched each child,
  falling back to a per-entry `git log -n1` for what the pass did not reach (bounded). Symlinks and submodules follow the
  recorded variants if any; otherwise documented departures.
- Paging: `X-Total-Count` is exact; `limit`/`page` clamps follow the F2a helpers (`page_params`, `paged`).
- Archive: `git archive --format=zip|tar.gz --prefix=<repo>/ <commit>` streamed from the child with the same supervisor
  pattern as the transport? **Decision:** buffer under a cap (`--max-archive-bytes`, default 256 MiB) in the git runner:
  the F2a runner already captures output with a cap; streaming archives is a later optimisation.

## Tests

Unit tests for each parser (log, numstat, ls-tree, for-each-ref) and e2e tests per route including: unknown/ambiguous ref,
ref that looks like an option (`--output=x`), path traversal (`../`, `.git/config`, NUL, `%2e%2e`), huge listing
(pagination), empty repo variants, non-UTF-8 file names and content, symlink to outside, submodule entry, a deleted
repository mid-read, private repo visibility (404 oracle parity), `public-only` token. The gate adds `D` and `E`
and removes the contents/tags defers of J, K, N.

## Order of work

1. refs + tags + commits list (paging, X-Total-Count) 2. git/commits get/.diff/.patch + trees 3. contents GET
4. archive 5. gate (D, E in; defers out), departures 6. threat-model addendum (output caps, argument hygiene) 7. reviews, PR.
