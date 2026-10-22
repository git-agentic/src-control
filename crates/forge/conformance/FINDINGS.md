# Findings from the Gitea recordings

Recorded 2026-10-22 against `gitea/gitea:1.22.6-rootless` and `1.26.2-rootless` with
`REQUIRE_SIGNIN_VIEW=true`, `FORCE_PRIVATE=true`, Actions, SSH and registration off. Scenario
letters match `fixtures/<version>/<letter>-*.json`. Every statement below was observed, not read
from source. "Both" means both versions answered the same.

Each version passes its own fixtures (22/22). Checking the 1.22.6 fixtures against 1.26.2 passes 3/22
(I, Q, V); every failure is a difference listed in the last table.

## Headline answers

- **Merge of a conflicting PR:** `405 {"message":"Please try again later"}`. Gitea sends the same text
  while a PR is still being checked, so status and body cannot tell the two apart.
- **Wrong `head_commit_id`:** `409 {"message":"head out of date"}`.
- **Required status check not met:** merge is `405`; 1.22.6 says `not allowed to merge [reason: Not all
  required status checks successful]`, 1.26.2 says `Not all required status checks successful`. Both
  contain "required status checks". A push to a protected branch is refused by the pre-receive hook
  (`Not allowed to push to protected branch main`, 1.22.6 prefixes `Gitea:`), for the admin too.
- **"already exists" texts:** repo `409 "The repository with the same name already exists."`; user and
  org `422 "user already exists [name: x]"`; PR `409 "pull request already exists for these targets
  [...]"`; branch `422 "branch already exists [name: ..]"`; file `422 "repository file already exists
  [path: ..]"`; branch protection `403 "Branch protection already exist"`; token name `400 "access
  token name has been used already"`; repo rename `422 "repository already exists [uname: acme, name:
  mixed]"`.
- **Foreign token (valid, no access):** API `404`, identical to a missing repo (1.22.6 body
  `{"errors":null,"message":"The target couldn't be found."}`, 1.26.2 `{"message":"not found"}`); git
  `404 "Repository not found"`. One leak: `git-receive-pack` on a missing org repo answers `403 "Push to
  create is not enabled for organizations."`. A bad or unknown token is `401` (1.22.6 `user does not
  exist [uid: 0, name: ]`, 1.26.2 `invalid username, password or token`). Anonymous: API `403 "Only
  signed in user is allowed to call APIs."`; git `401` with `WWW-Authenticate: Basic realm="Gitea"`.
- **Status de-duplication:** `commits/{sha}/status` keeps only the latest status per context;
  `commits/{sha}/statuses` and `statuses/{sha}` return the full history.
- **Merged immediately?** Yes. A GET right after `POST merge` shows `merged:true` with
  `merge_commit_sha`, and the merge commit has 2 parents.
- **`--force-with-lease`:** the check is client-side. With `refs/heads/b:` the push succeeds when `b`
  is absent and is refused locally (`stale info`) when it exists.

## By scenario

**A to D (meta, users, repos, empty repo)**
- No `WWW-Authenticate` on API 401s. `PATCH /admin/users/{u}` is 200. Token create returns
  `{id,name,sha1,token_last_eight,scopes}` (1.26.2 adds `created_at`).
- Scope enforcement is 403: a token with `read:user,read:organization,write:repository` cannot
  `POST /user/repos` (needs `write:user`) and cannot touch issue comments (needs `read:issue` or
  `write:issue`).
- The repo object has 58 keys; `permissions` is `{admin,push,pull}`.
- Empty repo: `commits` is `409 "Git Repository is empty."`; `GET branches` is 200 with the literal
  body `null`; `GET contents` is `200 []` on 1.22.6 and 404 on 1.26.2.

**E (history reads)**
- `git/refs/heads/{x}` is always an array. Contents `POST` is 201; `PUT` without `sha` is `422
  "[SHA]: Required"` on 1.22.6. Archive `.zip` starts `504b0304`, `.tar.gz` starts `1f8b0800`.

**F (pull requests)**
- `PATCH pulls/{n}` returns **201**. The `head=` filter on the PR list is ignored. `head.sha` follows a
  push immediately. A review with an unknown `event` is accepted as `PENDING`. A read-only
  collaborator's `APPROVED` is accepted with `official:false`. Approving your own PR is `422 "approve
  your own pull is not allowed"`. Issue comments need an all-scope token.

**G and T (merge)**
- Clean merge: 200, empty body. Retry after success: 405 with an empty message (1.22.6) or `"The PR is
  already merged"` (1.26.2). Closed PR: 404. `squash` and `rebase`: 1 parent; `rebase-merge`: 2.
  `fast-forward-only` when base moved: **500 with `{"message":""}`**. Head already contained in base:
  PR create accepted (201), merge 405. Unrelated histories: 409 with a `{Style,StdOut,StdErr,Err}` body
  (truncated, not valid JSON, on 1.26.2).
- After any base change Gitea re-checks open PRs and answers 405 "try again later" for a few seconds.

**H (statuses)**
- The POST response key is `status`, not `state`. Any state string is accepted and stored (`bogus`,
  empty). An unknown sha is 500 (1.22.6) or 404 (1.26.2). Combined state: success plus failure is
  `failure`; success plus pending is `pending`. No statuses: `state:""`, `sha:""` (1.22.6) or
  `state:"pending"` with the real `sha` (1.26.2).

**I and Q (protection)**
- Contents `POST`/`PUT` to a protected `main` is 403, even for the admin; with `new_branch` it is
  allowed. A merge through a PR is allowed. A forced push to `main` is rejected even with
  `enable_push:true`; deleting `main` by push is rejected. A force-push to an unprotected branch is
  allowed.

**J and V (git over HTTP)**
- Username is not checked: any username works with a valid token, as does the token as username with an
  empty password, and `-c http.extraHeader` with `Basic base64(TOKEN:)`, `token TOKEN` or `Bearer
  TOKEN`. A bad token gives `remote: Verify` (1.22.6) or `remote: Failed to authenticate user`
  (1.26.2). `Git-Protocol: version=2` returns a v2 advert. Fetch by sha works for the tip, an old
  commit and a deleted-branch tip over v0 and v2. `--filter=blob:none`, `--depth` and `--unshallow`
  work. gzip request bodies behave like plain ones. `info/refs` headers: `Cache-Control: no-cache,
  max-age=0, must-revalidate`, `Expires: Fri, 01 Jan 1980 00:00:00 GMT`, `Pragma: no-cache`.

**K and L (visibility)**
- Anonymous and bad-token probing cannot tell a missing repo from a private one, except the
  `receive-pack` case above. `PATCH private:false` is **accepted and stored** despite `FORCE_PRIVATE`;
  only creation is forced to private.

**M and N (names, default branch)**
- Duplicate repo names are case-insensitive (409). Rename leaves a redirect (307 on 1.22.6, 301 on
  1.26.2); the old name still works for git. `PATCH default_branch:"nope"` returns 200 and keeps `main`.
  An empty repo whose first push is a branch other than the default still reports `empty:true`.

**O and P (PR lifecycle, pagination)**
- Force-pushing the head moves `head.sha`. Deleting the head branch leaves the PR open;
  `refs/pull/N/head` stays visible and merge is 404. A merged PR's `head.sha` is **not** frozen: it
  follows a recreated branch. Pushing the head commit straight into base does **not** mark the PR
  merged (still open after 15 s). Default page size is 30, max 50; `limit=0`, `-1` and `abc` fall back
  to the default. PR lists are newest first.

**R and S (token scopes, special refs)**
- A `public-only` token on a private repo is `403 "token scope is limited to public repos"` (1.22.6) or
  `404` (1.26.2). Basic auth with a **token** as the password works on `/users/{u}/tokens`. Alice's
  password on `/users/bot/tokens` is 403. A `write:organization` token cannot create a repo in an org
  the user is not in. A write collaborator may push `refs/replace`, `notes`, `changes`, `keep-around`,
  `custom` and tags. `refs/pull/*` and `refs/for/*` are rejected; a branch literally named
  `pull/1/head` is accepted.

**U (status-check edges)**
- A success on a different sha is refused. `warning`, `error`, `failure`, `pending` and a success on
  another context are refused. **`skipped` on the required context allows the merge.** After the head
  moves, the old status no longer counts.

## Differences between the versions

| Area | 1.22.6 | 1.26.2 |
| --- | --- | --- |
| Not-found API body | `{"errors":null,"message":"The target couldn't be found."}` | `{"message":"not found"}` |
| Bad-token API message | `user does not exist [uid: 0, name: ]` | `invalid username, password or token` |
| Scope-error text | `...scope(s): [write:repository]` | `...scope(s), required=[..], token scope=..` |
| Repo object | has `parent` and `repo_transfer` (null), `default_allow_maintainer_edit:false` | omits both, `default_allow_maintainer_edit:true` |
| PR object | `assignees`, `requested_reviewers` null; list items include `additions/deletions/changed_files` | arrays; list items omit those three |
| Email in comments and statuses | `bot@noreply.localhost` | `3+bot@noreply.localhost` |
| Token and branch-protection objects | no `created_at`, no `priority` | adds `created_at` and `priority` |
| Empty repo `GET contents` | `200 []` | 404 |
| `GET commits?sha=nope` | 500 | 404 with body `null` |
| `PUT contents` without sha | `422 [SHA]: Required` | `422 repository file already exists` |
| Merge retry after success | 405, empty message | 405 `The PR is already merged` |
| Combined status, no statuses | `state:""`, `sha:""` | `state:"pending"`, real `sha` |
| Combined status, unknown sha | 200 empty | 404 |
| Non-member's permissions in a private org | 404 | 200, all false |
| Read team member's `can_read` | true | false |
| Rename redirect | 307 | 301 |
| Web page for a user without access | 303 to login | 404 |
| Org name `admin` | 422 reserved | 201 |
| Repo names `..` and `a..b` | 422, 201 | 500 both |
| Delete default branch | `can not delete default branch` | `can not delete default or pull request target branch` |
| Unrelated-histories merge body | valid JSON | truncated or empty |
| Merge when head not yet checked | sometimes 405 | 200 in this run |

## Not recorded or partial

- SSH, LFS, Actions, webhooks, releases, labels, milestones and issues other than comments.
- `mergeable` is compared by type only, since it flips while a PR is checked; the conflict state is
  kept as the note `conflicting_pr_mergeable_after_8s`.
- A non-fast-forward push to a protected branch is refused by the git client before it reaches the
  server, so only the forced variants exercise the server.
- Which of two same-second rows lists first (tokens, statuses, branches) is arbitrary on some versions;
  scenarios sleep 1.1 s between creations where order is compared.

## Operational notes

- A full record run takes about 2.5 to 3 minutes per version and needs a fresh server (the merge
  scenario waits for Gitea's async PR checks and is the slowest, about 45 s).
- Fixtures are 3.5 MB across the two versions; compact JSON would roughly halve that.
