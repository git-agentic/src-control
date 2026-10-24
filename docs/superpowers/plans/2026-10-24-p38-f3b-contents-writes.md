# P38 F3b: contents writes (plan)

`POST`, `PUT` and `DELETE` on `/repos/{o}/{r}/contents/{path..}`: server-made commits in a bare repository. This is
the first F3 code that writes objects and refs for a client over the API. Recorded exchanges: E#36 to #43 (create,
duplicate, update, stale sha, missing sha, `new_branch` from create and update, duplicate branch), B#27/28 (read-only
token 403, routed already), Q and W (protection, F4). Reviewed by Opus and Sol (see "Decisions after independent
review" at the end, which supersedes anything earlier in this file that it contradicts).

## Request and response

- `POST` creates, `PUT` updates, `DELETE` deletes a file. Body JSON: `content` (base64; required for POST and PUT, 422
  when missing or not a string), `message`, `branch`, `new_branch`, `sha` (PUT and DELETE: the blob id being replaced or
  removed). `author`, `committer`, `dates` and `signoff` are accepted and **ignored** (the authenticated user is the
  identity; departure entry); `from_path` (rename) is refused with 422; other unknown keys are ignored. An empty
  `branch` or `new_branch` is absent, and `new_branch` equal to `branch` is absent.
- Success: 201 (POST) / 200 (PUT, DELETE) with `{content, commit, verification}`. `content` is the contents object of
  the written file at the new commit (`null` for DELETE), `commit` is the flat file-commit object `{url, sha, created,
  html_url, author, committer, parents[{url,sha,created}], message, tree{url,sha,created}}` with the **real** tree id
  (not F3a's commit-id quirk), `verification` the unsigned object. The whole response is built in memory before the ref
  moves; nothing is read from git afterwards.
- `message`: trailing whitespace trimmed and one `\n` added (recorded `"add new.txt\n"`); empty means `Add|Update|Delete
  <path>`; NUL is 422.
- Recorded errors: POST on an existing path 422 `repository file already exists [path: p]`; PUT without `sha` 422
  `[SHA]: Required`; stale `sha` 422 `sha does not match [given: g, expected: e]`; `new_branch` that exists 422
  `branch already exists [name: n]`. Added: missing `branch` 404 `branch does not exist [name: b]`; PUT or DELETE of a
  missing path 404 `repository file does not exist [path: p]` (unrecorded; Gitea 1.22 may answer 500); bad base64,
  invalid path or branch name, a path blocked by a non-tree parent: 422 naming the path.

## Semantics

- `branch` is the base (default: the default branch **from the row read under the lock**). Without `new_branch` the
  commit advances `branch`; with it the commit is parented on the base tip and creates `new_branch`, which must be a
  valid branch name that neither exists nor collides (equal, a path prefix of, or prefixed by) with an existing branch
  name; checked before any object is written (422).
- **Unborn default.** If the base is the default branch and it does not resolve (the F3a/`empty` definition, whatever
  other branches exist), POST writes a parentless commit and creates the default branch. This is how a portal seeds an
  `empty: true` repository. PUT and DELETE there are 404 `branch does not exist`; `new_branch` from an unborn base is
  404. A missing non-default base is 404.
- Only regular files: new files `100644`; PUT keeps an existing `100755`; PUT/DELETE of a symlink, gitlink or directory
  is 422; POST on any existing entry, or under a parent that is a non-tree entry, is 422.
- **Path rules** (before any git call): `valid_path`, no `\`, no trailing `/`, at most 64 components, each at most 255
  bytes, none a `.git` alias (case, trailing dots/spaces, `:stream`, `git~1`, HFS-ignorable code points) and none a
  `.gitmodules` alias (same normalisation, `gitmod~1`): **`.gitmodules` cannot be written through the API** (422;
  its fsck checks on URL/path/name only run for pushes). `.gitattributes` content is refused when a line exceeds
  2048 bytes (fsck's `gitattributesLineLength`). The guarantee is git-metadata aliases only; Windows device names,
  `:` inside a name and case-fold collisions between siblings are not prevented (threat model).
- **Identity.** Author and committer: the authenticated user's `login` and stored email, else
  `<login>@noreply.localhost`; dates are one server timestamp passed to git explicitly so the response matches the
  commit exactly.
- **Size.** The JSON body limit (`--max-body-bytes`, 1 MiB) bounds the content. Operation limits: at most 64 path
  levels, 16 MiB of raw tree listing per level and 64 MiB cumulative, 60 s for the whole operation (checked between
  steps), 3 publication attempts. Free disk is checked against the same floor as pushes (`--min-free-bytes`) with a
  reservation for the content plus rebuilt trees.

## Algorithm (object ids and raw bytes only; bare repository, no index file)

**Lock order, everywhere, once each:** the per-repository **write gate** (timed `Gate(1)`, 503 `try again` when
busy, in the same per-id map as the lifecycle lock so `delete` drops both), then the shared lifecycle lock via a new
`Lifecycle::with_write_row` that returns the fresh `live` row (default branch included). The lifecycle lock is never
re-acquired beneath it and never upgraded; helpers below this boundary use no `read_locked`. Recorded in the
`lifecycle.rs` module doc as the rule for F4.

1. Validate everything cheap (path, names, base64, message, fields) and check the protection policy once early
   (Gitea's order: protection before preconditions).
2. Resolve the base: `rev-parse --verify` of `refs/heads/<branch>` to `old`, or unborn per the rules above. For
   `new_branch`, list branches and check collisions.
3. Walk the path from `old^{tree}` with raw `ls-tree -z` (no `-l`), one level at a time, parsed as **bytes**
   (`mode`, `type`, `oid`, name bytes). Check preconditions on these entries (exists / kind / `sha`).
4. `hash-object -w --no-filters --stdin` for the blob (reused on retries); rebuild directories bottom-up with `mktree -z`
   from the same raw entries with the one entry replaced, added or dropped (an emptied directory is dropped from its
   parent); names are never decoded. A `mktree` failure (it rejects a gitlink whose id is a blob) is 422
   `directory cannot be rewritten` with nothing published. Modes git itself canonicalises on listing (`100664`) are
   normalised in rebuilt directories only; untouched subtrees keep their ids.
5. `commit-tree <tree> [-p old]`, identity and dates in the environment, message on stdin.
6. **Protection seam:** `policy::check_update`'s sibling for contents (`check_contents_write(target, creating)`) is
   evaluated for the *target* ref on every publication attempt, including `new_branch`; today it permits. The `.sc`
   hook path and this one share the module so F4 adds a rule once.
7. `update-ref refs/heads/<target> <new> <expected>` (`expected` is `old`, or the zero id to create). **Outcome table**
   (re-read of the target ref after any failure; a re-read that itself fails is 500, never "missing"; every failure is
   logged with stderr, and a message naming a `.lock` file gets an operator hint):
   - ref now equals `new`: success (covers a killed process whose update landed);
   - advance, ref gone: 404 `branch does not exist`;
   - advance, ref changed: lost round, back to step 2 for the new tip (preconditions re-evaluated: the PUT/DELETE
     `sha` must still match, a POST path must still be absent; the blob is reused);
   - advance, ref unchanged and stderr names a held lock: lost round after 50 ms;
   - create of `new_branch`, ref exists: 422 `branch already exists`;
   - bootstrap create of the default branch, ref exists: lost round (advance on the new tip);
   - create blocked by a ref D/F conflict that raced the early check: 422 `branch already exists`;
   - anything else: 500.
   After 3 rounds: 409 `the branch was changed concurrently, try again` (no "conflict" in the text: clients read it as a
   merge conflict).
8. Log-only after publication: `repos::touch`. Respond from the prebuilt values.

Crash safety: objects first, ref last; failures and lost rounds leave unreferenced objects (no automatic gc runs;
`gc` is F5). No temporary files exist.

## Tests

Unit (`gitwrite`): path rules (git's t0060 style vectors for `.git`, `.gitmodules` and aliases, depth, length), raw
tree parse/rebuild round trip with non-UTF-8, tab and newline names and a legacy mode, message normalisation,
`.gitattributes` line limit, the publish loop against a fake ref store (lost rounds, exhaustion, killed-but-landed,
gone, locked).
E2E (`e2e_write.rs`, real git reads the result back): create/update/delete round trips visible to `git clone` and the F3a
reads; nested create; delete prunes emptied directories; `100755` kept; symlink, gitlink and directory refused; D/F both
ways; stale, missing sha; `new_branch` exists / is a prefix of / is under an existing branch; an untouched sibling with a
non-UTF-8 name and one with tab+newline keep their exact bytes; first commit in an empty repository; unborn default
with another branch present; PUT on unborn 404; read-only token 403; non-collaborator 404; an independent real git
ref writer racing API writes (assert ancestry and both files after a retried success, or the 409); the exhaustion
case publishes nothing from the API; a response never depends on a git call after the ref update; `fsck --strict`
clean; busy runner 503 with no ref change; a queued repository delete does not deadlock with a write; the
response `commit.tree` matches `git cat-file`.
Conformance: remove E's stop and defers (E#36 to #43) and the POST/PUT 501 stubs; DELETE gets an implementation with
no recorded exchange (unrecorded in the spec). Spec text for "Contents write" is updated in the same PR (`mktree`, not
a temporary index; `.gitmodules`; `noreply.localhost`).

## Decisions after independent review

Opus and Sol both reviewed this plan (first version used `gitobj`'s lossy listing and a mutex-then-lock order).
Accepted: byte-preserving tree handling (B1, Sol 1); full `update-ref` outcome table and branch-collision pre-check
(B2); depth/size/time limits and disk floor (B3, Sol 3); the unborn-default rule above (B4; Opus's "base is the unborn
default" over Sol's "genuinely empty" because sc-forge itself leaves `empty: true` repositories with other branches
after a push); lock order and one fresh row under the guard (Sol 4, 5, Opus discussion 1); response built before the
ref moves, touch log-only (Sol 6, Opus 2); `.gitmodules` refused and `.gitattributes` line limit (Sol 2, Opus 3);
`new_branch` equal to `branch` is absent; stale-lock hint; protection checked for the target on every attempt including
`new_branch`, and early in Gitea's order.
Disagreement: `author`/`committer`/`dates`. Sol: refuse with 422. Opus: accept and ignore, since refusing known Gitea
fields breaks clients that send them while the identity is the authenticated user either way. Decision: ignore, with a
`departures.json`-style note in the spec; `from_path` is refused because ignoring a rename leaves a copy.
Not done: portable-name collision rules (documented limit); sharing the push disk reservation beyond the free-space
floor; a temporary-index route (rejected: it also canonicalises modes and costs a file per request).
