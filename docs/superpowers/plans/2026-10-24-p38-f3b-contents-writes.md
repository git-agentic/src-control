# P38 F3b: contents writes (plan)

`POST`, `PUT` and `DELETE` on `/repos/{o}/{r}/contents/{path..}`: server-made commits in a bare repository. This is
the first F3 code that writes objects and refs on behalf of a client over the API, so the plan is reviewed before code
(Opus and Sol). Recorded exchanges: E#36 to #43 (create, duplicate, update, stale sha, missing sha, `new_branch` from
create and update, duplicate branch), B#27/28 (read-only token 403, already routed), Q and W (protection, F4).

## Request and response

- `POST` creates, `PUT` updates, `DELETE` deletes a file. Body JSON: `content` (base64, not for DELETE), `message`,
  `branch`, `new_branch`, `sha` (PUT and DELETE: the blob id being replaced or removed). `author`, `committer`,
  `dates`, `signoff` and `from_path` are **refused with 422** when present (departure: impersonation and rename are not
  built); an unknown key is ignored.
- Success: 201 (POST) / 200 (PUT, DELETE) with `{content, commit, verification}`. `content` is the contents object of the
  written file at the new commit (`null` for DELETE), `commit` is `{url, sha, created, html_url, author, committer,
  parents[{url,sha,created}], message, tree{url,sha,created}}` with the real tree id, `verification` the unsigned object.
  `message` is stored with one trailing newline (recorded `"add new.txt\n"`); empty means `Add|Update|Delete <path>`.
- Recorded errors: POST on an existing path 422 `repository file already exists [path: p]`; PUT without `sha` 422
  `[SHA]: Required`; PUT with a stale `sha` 422 `sha does not match [given: g, expected: e]`; `new_branch` that exists
  422 `branch already exists [name: n]`. Added (Gitea texts where known): `branch` missing 404 `branch does not exist
  [name: b]`; PUT or DELETE of a missing path 404 `repository file does not exist [path: p]`; bad base64 or NUL in the
  message or invalid path/branch name 422.

## Semantics

- `branch` is the base (default: the repository's default branch). Without `new_branch` the commit advances `branch`;
  with it the commit is parented on the base tip and creates `new_branch`, which must not exist. In a repository with no
  refs at all, a POST to the default branch (or none named) writes the first, parentless commit.
- Only regular files: new files are `100644`; PUT keeps the existing mode (`100644` or `100755`) and refuses a symlink,
  submodule or directory at the path (422); POST refuses a path that exists as anything, or that has a file as a
  parent directory (422 naming the blocking path).
- **Path rules** (stricter than reads, checked before any git call): `valid_path`, no `\`, no trailing `/`, each
  component at most 255 bytes, and no component that is `.git` or `git~1` after dropping HFS-ignorable code points
  (U+200C..200F, U+202A..202E, U+206A..206F, U+FEFF), trailing spaces and dots, and anything after a `:`, compared
  ASCII case-insensitively. Names that git or a checkout on macOS/Windows would treat as `.git` can never be created
  by this API (a push can still carry them; `receive.fsckObjects` covers that side).
- **Identity.** Author and committer are the authenticated user (`login`, stored email, else
  `<login>@noreply.localhost`, as auto-init); no other source. Dates are the server clock.
- **Size.** The JSON body limit (`--max-body-bytes`, 1 MiB) bounds the content; documented, not raised.

## Algorithm (all on object ids; bare repository, no index file)

Under the repository's **shared** lifecycle lock (a delete or default-branch change waits) plus a per-repository
**writer mutex** (new: serializes the server's own ref writes, as the spec's "per-repo write lock"); the git runner
gate applies to every command (busy is 503, nothing half-done because refs move last).

1. Validate everything cheap (path, names, base64 decode, sizes, forbidden fields).
2. Resolve `refs/heads/<branch>` to `old` (`rev-parse --verify`), or note it unborn.
3. Walk the path with `ls-tree -z` one level at a time from `old^{tree}` to find the current entry, the blocking
   parent, and each directory's entries. Check the preconditions (exists / sha / kind) on these entries.
4. `hash-object -w --no-filters --stdin` for the new blob; rebuild the directories bottom-up with `mktree -z` from the
   `ls-tree -z` listings with the one entry replaced, added or dropped (an emptied directory is dropped from its
   parent); untouched entries are copied verbatim, so unrelated subtrees keep their ids.
5. `commit-tree <tree> [-p old]` with the identity in the environment and the message on stdin.
6. **Protection point:** `policy::may_write_branch(...)` is called with the target branch immediately before the ref
   update; today it permits (rules arrive in F4 and plug in here, evaluated at this point as the spec says).
7. `update-ref refs/heads/<target> <new> <expected>` where `expected` is `old` (advance) or the zero id (create). Failure
   is classified by re-reading the ref: for an advance, a changed tip means CAS lost: loop to step 2 for the new tip
   (preconditions re-evaluated: the PUT/DELETE `sha` must still match, a POST path must still be absent), at most 3
   attempts, then **409** `the branch was changed concurrently, try again`; for a create, an existing ref is 422
   `branch already exists`; anything else is 500 with the stderr logged.
8. Stamp `updated_unix` (`repos::touch`) and answer. The response is built from the new commit, not re-read from a ref.

Crash safety: objects first, ref last; a crash leaves unreferenced objects (harmless). No temp files exist.

## Tests

Unit (`gitwrite`): path rules table (`.git`, `.GIT`, `.git.`, `.git `, `git~1`, `.g‌it`, `.git::$INDEX_ALLOCATION`,
`a\b`, trailing slash, long component), message normalisation, tree rebuild helper on nested trees.
E2E (`e2e_write.rs`, real git reads back the result): create/update/delete round trips visible to `git clone` and to
the F3a reads; nested create makes intermediate trees; delete prunes emptied directories; `100755` kept on PUT;
symlink and submodule refused; D/F conflicts both ways; stale and missing sha; `new_branch` exists; first commit in an
empty repository; unborn default with other branches; read-only token 403 before anything; non-collaborator 404;
two concurrent writers to one branch both land (retry) and a third forced-stale writer gets the recorded 422; CAS
exhaustion path (test hook forcing the tip to move) gives 409 and leaves no ref change; a push racing a contents write
never loses either; the response `commit.tree` matches `git cat-file`; `git fsck --strict` clean after the run; the
busy runner is 503 with the ref unchanged; delete of the repository waits for a write.
Conformance: remove E's stop and defers (E#36 to #43) and the `POST`/`PUT` 501 stubs; DELETE gets a stub-free
implementation without a recorded exchange (not in the recordings: Gitea semantics from the 1.22 API, listed as
unrecorded in the spec).

## Open points for review

1. Walk with `ls-tree`+`mktree` rather than a temporary index: no temp file or env plumbing, gitlinks and legacy
   modes survive (checked with git 2.54). Does this hide a hazard the index route avoids?
2. Is the writer mutex worth it given the CAS loop (it serializes the server's own writers so retries are rare)?
3. 409 after three lost CAS rounds, versus waiting on the mutex longer.
4. Refusing `author`/`committer`/`dates` instead of honouring them.
