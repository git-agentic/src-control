# sc-forge conformance contract

A contract for the Gitea-compatible subset of `/api/v1` (plus git smart HTTP) that `sc-forge`
serves, **recorded from real Gitea** rather than written by hand. A scenario runner has three jobs:

- `record` runs every scenario against a real Gitea and writes normalized fixtures.
- `check` runs the same scenarios against any server and compares the result with the fixtures.
- `diff` compares two fixture directories offline, for example `1.22.6` against `1.26.2`.

`show` prints a readable digest of a fixture directory. Everything is Python 3 standard library plus
`git` and (for recording) Docker. Always run Python as `python3 -I`.

## Record against real Gitea

```sh
cd crates/forge/conformance
eval "$(./gitea-up.sh 1.22.6 rec)"          # sets BASE_URL, ADMIN_TOKEN, CONTAINER
python3 -I run.py record --base-url "$BASE_URL" --admin-token "$ADMIN_TOKEN" --out fixtures/1.22.6/
./gitea-down.sh "$CONTAINER"
```

`gitea-up.sh <version> <label>` starts a throwaway `gitea/gitea:<version>-rootless` container with
sqlite3, a random free host port and a random container name (`sc-forge-conf-<label>-<hex>`), and
prints `BASE_URL=... ADMIN_TOKEN=... CONTAINER=...`. The container runs with
`REQUIRE_SIGNIN_VIEW=true`, `DEFAULT_PRIVATE=private`, `FORCE_PRIVATE=true`, registration, SSH and
actions disabled, and `OFFLINE_MODE=true`. The admin user is `siteadmin` because Gitea reserves
`admin`. `gitea-down.sh` refuses any container whose name does not start with `sc-forge-conf-`.

A full record run needs a **fresh** server: scenarios create `alice`, `bot`, `carol`, `dave`, the org
`acme` and repos such as `alpha` and `hist`. The images must already be pulled.

## Check any server

```sh
python3 -I run.py check --base-url http://127.0.0.1:3000 --admin-token "$TOKEN" --fixtures fixtures/1.26.2/
python3 -I run.py check ... --only F,G -v          # a subset, verbose
python3 -I run.py diff fixtures/1.22.6 fixtures/1.26.2   # offline version diff
python3 -I run.py show fixtures/1.26.2 --only G --body    # what was recorded
```

`check` exits non-zero on any failure. Requirements on the server under test: a fresh instance whose
admin token has all scopes, the ability to create users through `POST /admin/users` and tokens
through `POST /users/{u}/tokens` with Basic auth, and git smart HTTP on the same base URL.

### What is compared

Each scenario is a fixed sequence of exchanges (HTTP calls, `git` commands, and recorded
observations called notes). Exchange N of the run is compared with exchange N of the fixture:

- HTTP: method and normalized path, status (exact), the recorded response headers
  (`content-type`, `x-total-count`, `link`, `www-authenticate`, `location`, plus any a call tracks),
  and the body.
- JSON bodies: every recorded key must exist with the same type, extra keys are allowed, arrays must
  have the same length, and every scalar is compared by **value** after normalization. Only volatile
  values are compared by type: `message` and `errors` (text), every `url`/`*_url` key (they carry the
  host), a repo `size`, and paths a call lists in `volatile=[...]`.
- `message` text is checked with `must_contain=[...]`: each word must appear, case-insensitively,
  in the response message.
- Text bodies (diffs, patches) are compared exactly unless the call marks `volatile=["$text"]`.
- git commands: exit status (ok or not) and `must_contain` words in the combined output.
- Notes: recorded observations such as `merged_within_10s`. A note marked `strict=False` (timing)
  only warns.

### Normalization

Fixtures never contain tokens, passwords, host names, ports or real hashes:

| Real value | Placeholder |
| --- | --- |
| 40-hex object id | `<sha#N>` |
| numeric id (`id`, `*_id`, numeric path segment) | `<id:NAMESPACE#N>` |
| timestamp | `<ts>` |
| token, password | `<token>` |
| base URL / host:port / temp dir | `<base>` / `<host>` / `<tmp>` |
| the admin user name | `<admin>` |
| abbreviated hash ranges in git output | `<short>..<short>` |

Numbers `N` count first appearances, so two different shas stay different and the same sha stays the
same. Shas and numeric path segments (`/pulls/3`) are numbered **per scenario**; ids inside a JSON body
are numbered **per exchange** (ids of different kinds collide numerically, so cross-exchange body-id
identity would be accidental). `check` does not require the same numbers, only the same pattern: it
keeps a one-to-one mapping between fixture placeholders and actual values and reports an identity
mismatch when that mapping breaks. Numbering is assigned in sorted-key order, so a server's JSON key
order does not matter. Nothing else is sorted: array order is part of the contract.

## Scenarios

| Id | Topic |
| --- | --- |
| A | version, healthz, bad and missing credentials |
| B | users, orgs, tokens, token scope enforcement |
| C | repo create/get/patch/search/delete, collaborators, pushes by permission |
| D | reads on an empty repo |
| E | reads on a repo with history, contents API writes, archives |
| F | pull requests: create, list, head tracking, close/reopen, reviews, comments |
| G | merge outcomes and styles, `head_commit_id`, required status checks |
| H | commit statuses: dedupe, combined state, state strings, bad shas |
| I | branch protection CRUD and push enforcement |
| J | git smart HTTP: credential variants, sha fetch, partial/shallow clone, force-with-lease, tags |
| K | anonymous and foreign-token probing of missing vs private repos |
| L | `private:false` under `FORCE_PRIVATE` |
| M | name rules: case, reserved names, rename |
| N | default branch changes and first-push behaviour of empty repos |
| O | PR head lifecycle: force-push, deleted branch, recreated branch, direct push into base |
| P | pagination: order, `limit`/`page` edge cases, `Link`, `X-Total-Count` |
| Q | protection bypass paths: contents API, PR merge, force push, deletion |
| R | token scope edges |
| S | which special refs a write collaborator may push |
| T | merge outcome table: unrelated history, identical tree, contained head, conflicts |
| U | status-check edge cases: other commit, warning/skipped/error, moved head |
| V | raw smart HTTP bytes and headers, gzip request body |

## Add a scenario

Add a function to `run.py` before the `__main__` guard:

```python
@scenario("W", "my-topic")                 # id, file slug; base=False skips the shared setup
def sc_my_topic(c):
    c.mk_repo("thing")                     # unrecorded setup: users, org, repo, collaborators
    r = c.call("POST", "/repos/acme/thing/pulls", {...}, as_="bot-scoped",
               expect=201,                 # assert, for setup only; no expect means "just record"
               must_contain=["already exists"],   # words the message must carry
               volatile=["mergeable"])     # compare these paths by type only
    c.note("merged_within_10s", bool(ok))  # record a derived fact; strict=False for timing
    c.git(["push", url, "HEAD:refs/heads/x"], cwd=wc, name="push-x")   # recorded git step
```

Helpers: `c.call(..., rec=False)` for setup; `c.push_branch(repo, branch, files, base=...)` for
commits via real git; `c.mk_token`, `c.mk_user`; `mkpr`, `wait_for`, `advance_main` for PR flows.
Principals are named: `admin`, `alice`, `bot`, `carol`, `dave` (all scopes), `bot-scoped`
(`read:user,read:organization,write:repository`), `alice-ro` (`read:repository`), `none`, `bad`, and
`<name>-tokbasic` (a token sent as a Basic password, as git does).

Keep a scenario deterministic: no recorded call inside a data-dependent loop. Poll with unrecorded
calls and record the outcome as a note. Then record on both Gitea versions and review with `show`
and `diff` before relying on a new scenario.

Timing facts the scenarios already work around: Gitea answers a merge with `405 "Please try again
later"` while a PR is being checked and, indefinitely, when it has conflicts (`retry_while` in
`call()` retries only the first case); several versions list rows created in the same second in
arbitrary order, so scenarios that compare list order sleep between creations.
