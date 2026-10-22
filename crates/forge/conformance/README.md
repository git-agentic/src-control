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

## Fixture hygiene

`record` ends with a scan of the written files and fails on URL user-info (`://user:pw@`), auth headers,
raw 40-hex ids and any known token or password. Scenario error texts, git command lines and timeouts are
scrubbed before they are stored; git clones are cached per principal, so a collaborator's push never runs
with the admin's credentials.

## Check any server

```sh
python3 -I run.py check --base-url http://127.0.0.1:3000 --admin-token "$TOKEN" --fixtures fixtures/1.26.2/
python3 -I run.py check ... --only F,G -v          # report only F and G (all scenarios still run)
python3 -I run.py diff fixtures/1.22.6 fixtures/1.26.2   # offline version diff
python3 -I run.py show fixtures/1.26.2 --only G --body    # what was recorded
```

`check` exits non-zero on any failure. Requirements on the server under test: a fresh instance whose
admin token has all scopes, the ability to create users through `POST /admin/users` and tokens
through `POST /users/{u}/tokens` with Basic auth, and git smart HTTP on the same base URL.

`--only A,F` still **runs every scenario**, in order, because later scenarios read state created by earlier
ones (users, orgs, repos, `search` results); it only filters what is reported (check) or written (record).
An unknown id exits with status 2. `run.py diff` exits 1 when the two fixture sets differ.

### What is compared

Each scenario is a fixed sequence of exchanges (HTTP calls, `git` commands, and recorded
observations called notes). Exchange N of the run is compared with exchange N of the fixture:

- HTTP: method and normalized path, status (exact), the recorded response headers
  (`content-type`, `x-total-count`, `link`, `www-authenticate`, `location`, plus any a call tracks),
  and the body.
- JSON bodies: every recorded key must exist with the same type, extra keys are allowed, arrays must
  have the same length, and every scalar is compared by **value** after normalization. That includes
  commit, review and status `message`/`body`/`description` content and every `url`/`*_url` (html_url,
  clone_url, ssh_url, commit_url, target_url, ...) once the base URL is `<base>`, so a response that names
  the wrong repository fails. Only an explicit allowlist (`DEFAULT_VOLATILE` in `run.py`, with a comment
  per entry) and the dotted paths a call lists in `volatile=[...]` are compared by type: `avatar_url`
  (avatar hash), `mergeable` (flips while a PR is checked), `language` and the open-PR/issue counters
  (computed asynchronously), repo `size`. The top-level `message`/`errors` of an HTTP error response are
  compared as text (next bullet). Database counters inside URL fragments (`#issuecomment-7`) are
  normalized to placeholders.
- Error text: for every recorded exchange with status >= 400 whose body has `message` (or a non-empty
  `errors`), the actual text must equal the recorded text after normalization: lower case, and only
  id-shaped trailing details dropped (`[uid: 0, name: ]`, `[id: x, rel_path: ]`, numeric `id:`/`issue_id:`
  pairs). Other brackets are kept, so `[name: alice]` and `[write:user]` vs `[read:user]` stay distinct.
  Placeholders such as `<sha#3>` are kept and compared with the scenario's identity mapping, so a message
  naming a different sha fails. A recorded `errors: []` requires the actual `errors` to be empty or absent.
  A failing exchange prints both texts. `must_contain=[...]` is an additional check.
- Text bodies (diffs, patches) are compared exactly unless the call marks `volatile=["$text"]`.
- Archives (`binary=True` calls answered 200): the zip or tar.gz is parsed and its entries are compared by
  normalized name, size and SHA-256 of the content, so a server that only sends the 4-byte signature fails.
- git commands: exit status (ok or not) and, for a failing step, the refusal text: the recorded
  `remote:`/`fatal:`/`error:`/`!` lines (normalized, without hosts and ids) must all appear in the actual
  output, so a push refused for another reason fails. `must_contain` words are checked too.
- `ls-remote --symref` steps record their normalized stdout as a strict note (`<step>_stdout`).
- Notes: recorded observations such as `merged_within_10s`. A note marked `strict=False` (timing, or a
  race kept for the record) is stored but never compared.
- Repo fields Gitea updates asynchronously after a push (`empty`, `default_branch`) are read with
  `settle_keys`: the call polls until 8 consecutive reads (4 s) agree, for at most 25 s, and records that
  value; the first read is kept as a non-strict note. If the value does not settle in 25 s the exchange
  **fails** (record mode raises). `check --strict-first-read` additionally fails when the first read
  differs from the settled value (for a server that has no such lag, such as sc-forge).

### Departures and the gate

sc-forge's CI gate is `fixtures/1.22.6` plus `departures.json`. `fixtures/1.26.2` is reference only, for
the version rule: follow 1.22.6 unless it answers 500, an empty message or a malformed body, in which
case follow 1.26.2. So `departures.json` has no version field and must cover every exchange where
1.22.6 recorded one of those and sc-forge follows 1.26.2 (unknown sha on `commits?sha=`, merge retry after
success, ...), as well as every deliberate sc-forge difference.

`departures.json` is a list of `{scenario, exchange, label, expect, reason}`. Pass it with
`check --departures departures.json` (never when checking real Gitea).

- `kind` (`http`, `git`, `note`) and `match` identify the exchange: `METHOD /path/template` as recorded
  (placeholders included), the git step name, or the note key. `match` is required for a single index.
  `exchange` is a fixture index, a list or range `"a-b"` (then `matches` is required, one per member), or a
  git step name / note key. Indexes are identical in `fixtures/1.22.6` and `fixtures/1.26.2`.
- The identity is enforced twice: a fixture exchange that no longer matches is a `stale departure`, and an
  override is refused (`applied to a different exchange`) when the exchange actually produced differs,
  including for `skip`.
- `expect` keys: `status` (number or list), `message_contains`, `ok` (git), `value` (note; works for
  `strict=False` notes too), `fields` (pin body values by dotted path, `$len` pins an array length),
  `ignore_fields` (dotted paths left out of the body comparison), `ignore_headers` (recorded headers left out),
  `ignore_body` (no body comparison at all) and `skip` (only when unavoidable; say why in `reason`).
- A departure replaces only what it names. Whatever it sets (`status`, `fields`, `message_contains`, ...), the
  recorded headers (minus `ignore_headers`) and every JSON field not in `ignore_fields` or `fields` are still
  compared, and a top-level error `message` is checked by `message_contains` instead of the recorded text.
  Only an explicit `ignore_body` drops the body comparison. If a departure moves the status across the
  2xx/4xx boundary (for example 201 to 422) the recorded body cannot match, so the run fails with
  "needs ignore_body with a reason" until the entry says so; the generator adds `ignore_body` and the reason
  in that case, plus `ignore_headers` for the headers that cannot exist on the other side (`location`,
  `x-total-count`, `link`, and `content-type` of a redirect).
- Load errors (the run aborts): unknown scenario id, unknown `expect` key, missing `reason`, `kind` or `match`,
  a range or list without matching `matches`, two entries for one (scenario, index), and any entry that
  expects a refusal (`status` >= 400 or `ok:false`) without `message_contains`, so a departure cannot hide
  a wrong error message.
- Run-time failures: `stale departure` (the index is out of range or the label no longer matches),
  `duplicate departure` (name-based entries that resolve to the same exchange) and `unexpected` (the actual
  answer does not meet `expect`). A met entry prints `expected difference honoured`.
- `message_contains` is enforced on refusals (actual status >= 400); `fields` on successful bodies.
- Scenario `expect=` assertions guard preconditions and only run in `record` mode (and for unrecorded setup
  calls). In `check` mode a recorded exchange that answers differently is a diff, never an abort.
- Teams (scenario B: create team, add member, carol's org permission) are tagged `team` and covered by
  departures because sc-forge has no teams. Basic-**password** auth on an ordinary API route (scenarios B,
  R, X) is covered by departures too: sc-forge accepts a password only on `/users/{u}/tokens*`.
- The `message_contains` words for sc-forge's own error texts (merge style, state, rename, branch) are
  placeholders: reword them when sc-forge's messages are fixed.

Not covered by a departure: the merge of a PR whose head is already in base. sc-forge reproduces Gitea's
`405 "Please try again later"` with `changed_files: 0`, so the recorded exchanges apply unchanged. The
combined status for a sha with no statuses (1.22.6 `state:""`, 1.26.2 `pending`) and for an unknown sha
(1.22.6 `200` with empty fields, 1.26.2 `404`) are not 500/empty-message/malformed cases, so the rule gives
no departure; add one when sc-forge's answer is decided.

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
| W | contents API and direct pushes on a protected branch with `enable_push:true`, with and without a required status check |
| X | token, Bearer and Basic auth forms on API routes; site admin password; read-only token as Basic password |

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
