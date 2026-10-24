# P38 F4: pull requests, statuses, branch protection and merge

Status: plan, before review. Spec: `docs/superpowers/specs/2026-10-22-p38-forge-design.md`
(sections "Merge", "Statuses", "Server-side Git operations", Appendix A). Contract: the
recorded fixtures (scenarios F, G, H, I, O, Q, T, U, W; P for paging) and `departures.json`,
which already carries the reviewed F4 departures. Built on F3b's seams: `policy::check_contents_write`,
`Lifecycle::with_write_row` (per-repository write gate, then the shared lifecycle lock), `gitwrite`
(`update_ref` CAS, `is_ancestor`, `classify`), `gitobj::resolve`.

## Intent

A Git forge that Engine can switch to by config: PRs with the Gitea object shapes, commit statuses,
branch protection that holds on every write path (push, contents API, merge), and a merge that is
crash-safe. F4 is too large for one reviewable PR (F2 and F3 were split the same way), so it ships as
three PRs, each with its own conformance gate letters, tests, independent review and docs:

| PR | Scope | Gate letters added | Pending removed |
|---|---|---|---|
| F4a | migration 3, branch protection CRUD, enforcement in the `pre-receive` hook, contents API and branch delete; commit statuses (POST, combined, lists) | H, I, W | B#30 |
| F4b | migration 4, pulls (create, list, get, PATCH, diff, patch, commits, files), reviews, review comments, issue comments, `refs/forge/pull/<n>/head` retention refs, mergeability cache; merge probe `GET /pulls/{n}/merge` | F, O (merge-independent exchanges), P | D#13 |
| F4c | `POST /pulls/{n}/merge`, merge intents, recovery at startup and under the write gate, required-status gating, kill -9 restore test, threat-model pass #2, protection-bypass tests across all paths | G, O, Q, T, U (all) | none |

Order matters: F4a's protection and statuses are inputs to F4c's merge gate; F4b's PR rows are inputs to
F4c's intents. Each PR leaves `main` consistent (routes of a later slice stay `not_implemented`, listed in
`slice-pending.json`).

## Cross-cutting decisions

1. **One decision point for ref moves.** `policy` grows `Rules` (the protection rules of one repository,
   loaded from SQLite) and `check_push(rules, name, old, new, is_ff)`, `check_contents_write(rules, target,
   creating)`, `check_branch_delete(rules, name)`. The hook, the contents API and the branch DELETE call these
   and nothing else decides. The merge (F4c) is deliberately *not* subject to `enable_push` (recorded: a PR merge
   into a protected branch is allowed), only to the status-check gate.
2. **Rule matching is exact, case-insensitive on the branch name** (`policy::same_branch_name`, the same
   alias rule F2b uses). Gitea also supports glob patterns in `rule_name`; the recorded clients use plain
   names. A `branch_name` or `rule_name` containing `* ? [ ]` is refused with 422 instead of being stored as a
   literal that protects nothing (fail closed). Departure entry.
3. **Unsupported protection settings are refused, not ignored.** The 1.22.6 object has ~30 keys. We implement
   `branch_name`/`rule_name`, `enable_push`, `enable_status_check`, `status_check_contexts`. Any other request
   field that is present with a non-default value (`required_approvals > 0`, `enable_push_whitelist`,
   `enable_merge_whitelist`, `block_on_*`, `dismiss_stale_approvals`, `require_signed_commits`, `protected_file_patterns`,
   ...) answers 422 `unsupported branch protection setting: <key>`. Echoing a setting we do not enforce would give
   a false sense of security. Responses carry the full recorded key set with the defaults of the unsupported
   keys.
4. **Semantics of `enable_push`** (recorded I, Q, W): `false`: nothing may move the branch except a PR merge — no
   push (admin included), no contents write, no deletion; branch creation by push is refused too (the name is
   reserved). `true`: a fast-forward push by anyone with write is accepted (also when `enable_status_check` is
   on and unmet: required checks gate merges, not pushes, W#8); a non-fast-forward push and a deletion are refused
   for everyone, admin included (Q#11, Q#12); contents writes are allowed (W).
5. **Linearization.** Rule create/PATCH/DELETE run under the per-repository write gate (`with_write_row`), so a
   server-made ref write (contents, F4c merge) checks its rules under the same gate immediately before
   `update-ref` and cannot interleave with a rule change. `receive-pack` does not take the gate; the hook reads
   the rules at `pre-receive` time. A rule added during an in-flight push can therefore be bypassed by that one
   push; git's ref transaction, not our gate, is the arbiter there (spec: "does not exclude receive-pack"). Stated
   in the threat model rather than closed.
6. **Hook fast-forward check.** `check_push` needs `is_ff` for `old != 0 && new != 0` on a protected branch with
   `enable_push=true`. The hook runs `git merge-base --is-ancestor <old> <new>` in the repository, with
   `GIT_DIR`, `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES` taken from its own environment
   (receive-pack's quarantine holds the incoming objects) and everything else scrubbed (same sanitized env as the
   runner, no config, no hooks). Exit 0 = ff, 1 = not ff, anything else or a failure to spawn = refuse
   (fail closed). Only spawned when a rule applies to that ref.
7. **Database access.** Every handler keeps the F1 rule: database errors are logged and answered as a bare 500.
   The hook opens the database read-only (existing `db::open_readonly`).
8. **Departures** (each gets a `departures.json` entry with reason where a recorded exchange differs): glob rule
   names refused (2), unsupported settings refused (3), status POST with unknown/missing `state` is 422 and an
   unknown commit is 404 (already recorded in departures), squash/rebase/ff-only merge styles 422 (already
   recorded).

## F4a: branch protection and statuses

### Schema (migration 3)

```
CREATE TABLE branch_protections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
  branch TEXT NOT NULL, lower_branch TEXT NOT NULL,
  enable_push INTEGER NOT NULL DEFAULT 0, enable_status_check INTEGER NOT NULL DEFAULT 0,
  status_check_contexts TEXT NOT NULL DEFAULT '[]',   -- JSON array of strings
  created_unix INTEGER NOT NULL, updated_unix INTEGER NOT NULL,
  UNIQUE (repo_id, lower_branch));
CREATE TABLE commit_statuses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
  sha TEXT NOT NULL, context TEXT NOT NULL, state TEXT NOT NULL
    CHECK (state IN ('pending','success','error','failure','warning','skipped')),
  description TEXT NOT NULL DEFAULT '', target_url TEXT NOT NULL DEFAULT '',
  creator_id INTEGER NOT NULL REFERENCES users(id),
  created_unix INTEGER NOT NULL, updated_unix INTEGER NOT NULL);
CREATE INDEX commit_statuses_by_sha ON commit_statuses (repo_id, sha, context, id);
```
`TABLES` in `db.rs` gains both names (healthz probes them). `repos::delete_row` already cascades.

### Protection API (`protection_api.rs`)

`GET|POST /repos/{o}/{r}/branch_protections`, `GET|PATCH|DELETE .../{name}` (name may contain `/`: a `{name..}`
tail). Actor `Repo(Admin)` for writes (recorded: write collaborator gets 403 "user should be an owner or a
collaborator with admin write of a repository"), `Repo(Read)` for reads. Scope `write:repository` /
`read:repository`. Status/texts as recorded: 201 create, 403 "Branch protection already exist", 404 "The
target couldn't be found." (use the existing `not_found`), 204 delete; GET list is an array (not paginated by
Gitea; none here). Body validated by key (3). `status_check_contexts` entries: strings, each ≤ 255 bytes, at
most 64 entries, no empty string (422). `enable_status_check` with no contexts is stored as given (recorded
Gitea accepts it; the merge gate then requires nothing).

`branches` JSON (`repo_api::branch_json`) reads the rule: `protected`, `enable_status_check`,
`status_check_contexts` (null when no rule, as recorded in Q), `user_can_push` (recorded false when
`enable_push=false` even for admin), `effective_branch_protection_name`, `required_approvals` 0.

### Enforcement

* `policy.rs`: `Rules` (list of `{branch, enable_push, enable_status_check, contexts}`), `Rules::for_branch(name)`,
  and the three checks of decision 1. Texts: push to a protected branch with `enable_push=false` →
  `Not allowed to push to protected branch <branch>` (recorded text minus Gitea's `Gitea:` prefix); force push /
  delete with `enable_push=true` → `Not allowed to force-push to protected branch <branch>` /
  `Not allowed to delete protected branch <branch>`; contents API → 403 `user cannot commit to repo [user: <login>]`
  (recorded Q#1-3); branch DELETE of a protected branch → 403 `protected branch, can not be deleted` (unrecorded; only the default
  branch's `can not delete default branch` is recorded and already built).
* `hook.rs`: `lookup` returns default branch, live flag and `Rules`; `decide` takes the rules plus an `is_ff` callback.
* `content_write.rs`: replace the two `check_contents_write(_, _)` calls with the rules-carrying form; the second
  call (immediately before `update-ref`) reloads the rules from SQLite on every attempt (a fresh read inside the
  write gate, which also serializes with rule changes).
* `lifecycle::delete_branch`: refuse a protected branch under the gate.

### Statuses (`status_api.rs`)

`POST /repos/{o}/{r}/statuses/{sha..}` (Write; scope `write:repository`), `GET .../commits/{ref..}/status`
(combined), `GET .../commits/{ref..}/statuses` and `GET .../statuses/{ref..}` (history), newest first
(highest id), paged like Gitea (`page`, `limit` ≤ 50, `X-Total-Count`; recorded H uses `limit=100`, capped).
`{sha}` resolves through `gitobj::resolve` (F3a grammar: HEAD, branch, tag, hex id), peeled to a commit; the
stored `sha` is the full commit id. Unknown → 404 (departure recorded). Reads of an existing commit with no
statuses: combined `state:"pending"`, real `sha`, `total_count:0` (recorded departure/1.26.2).

POST body: `state` (required, one of six, else 422), `context` (default `""`, as recorded H#36; ≤ 1024 bytes
else 422 — the recorded 300-byte context is accepted), `description` (≤ 1024 chars, 422 above), `target_url` (≤ 2048,
must be empty or an `http(s)://` URL, 422 otherwise; stops `javascript:` URLs that web clients render).
Response 201, key set recorded (`id,status,target_url,description,url,context,creator,created_at,updated_at`),
`creator` is the existing user JSON.

Combined state (recorded H#13-H#35): over the latest status per context, any `error` or `failure` → `failure`;
else any `pending` → `pending`; else any `warning` → `warning`; else `success` if any success; only `skipped` →
`skipped`. Unrecorded combos (`warning` alone, all-`skipped`) follow that order, noted in the spec.
Latest per context = highest `id`. Bounded growth: a (repo, sha, context) keeps at most 100 rows; inserting the
101st deletes the oldest in the same transaction (departure: history is bounded; a writer posting statuses in a
loop cannot grow the database without limit).

### F4a tests

* Unit: `policy` matrix (rules × push/force/delete/create/contents/branch delete, case aliases, glob refused),
  combined-state function (all pairs), body validators, hook `decide` with rules and an injected `is_ff`.
* E2E (`e2e_protection.rs`, real git): protected push refused for write collaborator and admin; ff push allowed with
  `enable_push=true`, force/delete refused; unprotected branch force-push allowed; contents API 403/allowed with
  `new_branch`; branch DELETE refused; rule change under concurrent contents writes (writer sees the new rule
  immediately after the PATCH returns); branch-name alias `MAIN` rule; statuses round trip incl. 100-row cap.
* Gate: add H, I, W; shrink `slice-pending.json` (B#30 off; Q/U/G still wait for merge, which F4c gates).

## F4b: pull requests, reviews, comments

### Schema (migration 4)

`repo_counters(repo_id PK, next_index)` (issue/PR numbers share one sequence per repository, as recorded:
`pulls#1` is `issues#1`), `pulls(repo_id, number, head_ref, base_ref, head_sha_at_open, title, body,
state open|closed, merged, merge_commit_sha, final_head_sha, changed_files_at_merge, creator_id, created_unix,
updated_unix, closed_unix, merged_unix, merged_by)`, `reviews(id, repo_id, pull_number, reviewer_id, state, body,
commit_id, official, created_unix)`, `review_comments(id, review_id, path, line, body, ...)`,
`issue_comments(id, repo_id, number, author_id, body, created_unix, updated_unix)`,
`mergeability_cache(repo_id, base_sha, head_sha, mergeable, changed_files)`. Indexed for newest-first listing and
the open `(repo, head_ref, base_ref)` uniqueness (409 "pull request already exists for these targets").

### Behaviours (recorded F, O)

* Create: head and base are branches of this repository (a `owner:branch` head naming this repo is accepted; another repo
  is 404 — forks are a non-goal). Errors as recorded: 404 `BaseNotExist`/target not found, 422 "There are no changes between
  the head and the base", 422 `[Title]: Required`, 409 duplicate open PR. Pushing the head to base later does not mark the
  PR merged (O#28).
* `head.sha` of an open PR is the live branch tip; a merged PR's `head.sha` is `final_head_sha` (departure O#20-22 recorded);
  a closed PR shows its last head (retention ref).
* PATCH returns **201** (recorded F#22): `state`, `title`, `body`, `base`. Reopening a PR whose head branch is gone is refused 404.
* List: newest first, `state=open|closed|all`, `head` ignored as in Gitea (clients filter), default limit 30, max 50, invalid
  limit falls back (recorded P), `X-Total-Count`.
* Mergeability and `changed_files` (open PRs): `merge-tree --write-tree` result cached by `(base_sha, head_sha)`; misses are
  computed under a concurrency limit of 2 and are skipped on list endpoints beyond the first 10 misses per request (the
  field is then the last cached value or null with `mergeable:true`: the recorded type-only comparison).
* `pulls/{n}.diff`, `.patch`, `/commits`, `/files` from `git diff`/`log` through `gitobj` (F3a has the diff and patch text
  helpers; `base...head` merge-base form). Capped by F3a's output caps (413).
* Retention refs `refs/forge/pull/<n>/head`: written by the server (never by clients; the hook already refuses the namespace)
  at create, at close and merge, and by `delete_branch` before it deletes a branch that is the head of an open PR. The ref is
  hidden by `transfer.hideRefs` already (F2b); `allowAnySHA1InWant` keeps fetch-by-sha working. A delete of such a branch by
  *push* is handled in `pre-receive` by writing the retention ref before the delete lands (the hook runs as the server user; a
  failed push leaves a harmless extra ref).
* Reviews: states map `APPROVED|REQUEST_CHANGES|COMMENT|PENDING` as recorded; unknown `event` is `PENDING` (F#27-30); own-PR
  approval 422 "approve your own pull is not allowed"; `official` is true only for write access holders. Review comments list
  from `reviews/{id}/comments`; inline comments in the review POST body stored (path, line, body).
* Issue comments `GET|POST /issues/{n}/comments`: scopes `read:issue`/`write:issue` (recorded 403 text), 201 on create.
* Locking: PR create/PATCH take the per-repository write gate (`with_write_row`) because they write retention refs; reads use
  `with_read`. Number allocation inside the same SQLite transaction as the insert.

### F4b tests/gate

Unit: PR JSON shape, list paging, review state machine. E2E (`e2e_pulls.rs`, real git): create/duplicate/no-changes,
force-push head follows, branch delete keeps PR and retention ref, close/reopen, reviews by role, comments, diff/patch bytes against
`git diff`. Gate: add F, O (merge exchanges stay pending until F4c), P.

## F4c: merge, intents, recovery

Implements the spec's "Merge" section as written (steps 1-7, crash recovery, `merge_intents` journal, stale-head and
nothing-to-merge answers, explicit 409 conflict, unrelated-histories 409, `Do` other than `merge` → 422, no admin bypass of
status checks). Plan-level decisions beyond the spec:

* **Schema (migration 5):** `merge_intents(id, repo_id, pull_number, base_ref, base_oid, head_ref, head_oid, merge_oid,
  state pending|done|aborted, created_unix)`. At most one pending intent per PR (UNIQUE partial index).
* **Lock order:** `with_write_row` gate (10 s, 503) → SQLite. The gate is held for steps 5-7. Recovery under the gate for a repository
  also runs in the startup reconciler before the listener accepts.
* **Merge commit** built by `commit-tree -p base -p head` on the `merge-tree --write-tree` tree, message and identity as spec; `GIT_*_DATE` pinned
  from the same clock as the intent row.
* **Status gate (step 3)** reads `commit_statuses` for `head_oid` only; latest per context; `success`/`skipped` satisfy. No bypass for admins.
* **Atomic ref step:** `update-ref --stdin` transaction with `verify` of the head and `update` of the base (spec step 6). Failure
  classification reuses `gitwrite::classify` (landed/lost/locked). Bounded recompute (2), then 405 "try again later".
* **Kill -9 test:** a harness that runs merges and pushes, sends SIGKILL at randomized points, restarts, and asserts for every PR that
  `merged` agrees with `merge_oid` being an ancestor of base and that no `pending` intent survives reconcile.
* **Threat-model pass #2** in `docs/THREAT-MODEL.md`: server-side writes, merge races, contents/push/merge protection parity, retention
  ref namespace, status trust, comment/body limits.
* **Protection-bypass matrix test** (`e2e_bypass.rs`): for each of {push, force push, delete, contents POST/PUT/DELETE with/without
  `new_branch`, branch DELETE API, merge} × {enable_push false/true} × {admin, write, read} against the expected outcome table.

## Verification and process (all three PRs)

* `cargo test -p scl-forge`, `forge-check.sh` (gate grows each PR), `cargo clippy -D warnings`, fmt; CI toolchain 1.96.1.
* Independent review per PR: Opus `code-reviewer` then Sol (`gpt-6.1-sol`) on F4a (auth/permissions) and F4c (data integrity); Opus on F4b.
* Docs per PR: spec "F4x decisions (as built)", THREAT-MODEL sections, ROADMAP, departures entries, memory update.

## Questions for the reviewers

1. Is "exact name, case-insensitive, globs refused" the right fail-closed choice, or should globs be implemented now?
2. Hook `merge-base --is-ancestor` in the quarantine environment: any hole (replace refs, grafts, `GIT_*` smuggling, alternates)?
3. Is bounding status history per context (100) acceptable, or does some client need the whole history?
4. Retention-ref writing in `pre-receive` for pushed deletes: acceptable, or should deletions of an open PR's head be refused/handled elsewhere?
5. Slicing: is moving the status gate into F4c (needs F4a statuses + F4b PRs) the right order?

## Decisions after independent review (Opus + Sol; this section overrides earlier text where they differ)

Both reviewers confirmed the protection semantics table (I, Q, W), exact-name matching with globs refused, the hook's
`merge-base --is-ancestor` check (with the conditions in R9) and the slicing order. Findings that changed the plan:

**Merge (F4c)**

* **R1. Revalidate under the gate.** Merge takes the gate first, then: run recovery for pending intents of this repository,
  re-read the PR (state, base, head ref), the protection rules and the required statuses, and only then insert the intent.
  Rule CRUD, PR PATCH and merges all hold the gate, so they are totally ordered; statuses do not take the gate, so the
  status check linearizes at its read inside the gate (a status posted after it is not counted). Rule CRUD answers 503
  while a merge holds the gate (documented).
* **R2. Durable receipt.** The step-6 `update-ref --stdin` transaction also creates `refs/forge/merge/<intent id>` =
  `merge_oid` (server-only namespace, already hidden and refused to clients). Recovery tests for the receipt, not for
  ancestry of the current base: receipt present = the transaction committed (finalize, even when the base was force-pushed
  away or deleted afterwards); receipt absent and intent pending = aborted. The receipt is deleted after the SQLite
  finalization (and by recovery). The kill -9 invariant is "no pending intent survives reconcile, `merged` ⇔ intent done,
  no receipt without a done intent", not "merge_oid is an ancestor of base" (a permitted force push breaks that).
* **R3. Complete intent row.** `merge_intents` also stores `merger_id`, `merged_unix`, `changed_files`, `additions`,
  `deletions`; `(base_oid, merge_oid)` is rewritten in a committed transaction before every `update-ref` attempt (a
  recompute changes `merge_oid`); recovery finalizes with exactly the fields a normal merge writes; the retention-ref write
  in finalization is idempotent; the table cascades on repository delete.
* **R4. Stale-head classification is merge's own.** `gitwrite::classify` is single-ref. The merge uses its own outcome
  function: reconcile the receipt first, then re-read head and base separately; changed head → 409 `head out of date`
  (never silently substituted), changed base → bounded recompute, then 405 `try again later`.
* **R5. Step 7 failure.** If the SQLite finalization fails after the ref landed, retry inside the gate; a read that finds a
  pending intent runs recovery inline when it can take the gate without waiting (otherwise reports not merged and leaves
  the intent), so the next request converges.

**Pull requests (F4b)**

* **R6. Deleting the head branch closes the PR** (fixtures O#6-O#10, O#24-O#25, both Gitea versions; the spec's and
  FINDINGS' "leaves the PR open" is wrong and is corrected in F4b's docs). Retention ref is written first, the PR is
  closed, `head.ref` reads `refs/pull/<n>/head` with `head.label` the branch name. Reopen is allowed (201) even when the
  branch is gone (O#26). Merge of such a PR is 404.
* **R7. Retention without a second writer process.** Instead of a `post-receive` hook doing database writes (the hook has a
  read-only handle), the server runs `pulls::sync(repo)` under the gate after every accepted push (accept marker, but
  refs are compared, not the marker trusted), contents write, branch API delete and at startup reconcile: for each open PR
  it CAS-updates `refs/forge/pull/<n>/head` to the head branch tip, or, when the branch is gone, keeps the retained head,
  closes the PR and records `final_head_sha`; for closed/merged PRs it repairs the ref to `final_head_sha`. The spec's
  `freezing` state is unnecessary because refresh and freeze are both gate-ordered in one process; spec updated when built.
  The `pre-receive` hook still records `old` into the retention ref (scrubbed env, quarantine variables removed, no object
  from the push is referenced) when a push deletes the head of an open PR, so a crash before `sync` cannot lose the tip;
  startup reconcile repairs any disagreement. Create writes the ref before inserting the row.
* **R8. Branch delete is a CAS.** `delete_branch` reads the tip, retains it, then deletes with expected old id; on mismatch it
  re-reads and retries (≤3) or answers 409. It reads protection rules under the exclusive lifecycle lock it already holds
  (never `with_write_row` from inside it: self-deadlock).

**Protection and hook (F4a)**

* **R9. Hook conditions.** Environment from `Git::env_with` (keeps `GIT_NO_REPLACE_OBJECTS`, `core.useReplaceRefs=false`);
  git binary path passed explicitly (the pinned `PATH` may not contain it); repository directory derived from
  `FORGE_DATA_DIR` + repo id, never from `GIT_DIR`; only `GIT_OBJECT_DIRECTORY` and `GIT_ALTERNATE_OBJECT_DIRECTORIES` are
  taken from the inherited environment and must lie under that repository; `old`/`new` validated as hex before argv;
  `GIT_PUSH_OPTION_*` and everything else scrubbed. Git refuses ref updates while `GIT_QUARANTINE_PATH` is set, so the
  retention write in R7 spawns without any `GIT_QUARANTINE_PATH`/object-dir variables.
* **R10. Refusal texts and departures.** The gate compares the refusal lines. Use the recorded text where it is ours to say
  (`not allowed to push to protected branch <b>`, `branch <b> is protected from force push`) and add a departure entry for
  the dropped `gitea:` prefix and for the default-branch delete wording (like the existing J#62 entry); every text that
  differs gets an entry, decided by running the gate.
* **R11. Protection tests use a non-default protected branch** for delete and force-push cases (Q#12/Q#15-16 target
  `main`, where the default-branch rule fires first); also creation of a previously absent protected name and contents
  `new_branch` targeting a protected name (stricter than Gitea, which checks only the old branch: departure note).
* **R12. Rule body.** `status_check_contexts`/`rule_name` handling per the fixtures: a branch with no rule reports
  `status_check_contexts: null`, a rule without contexts reports what Q#0/W#0 show (the gate decides; the column is
  nullable so the distinction survives); conflicting `branch_name` vs `rule_name` → 422; glob metacharacters refused in
  rule names on create and PATCH and in context names. `enable_status_check` with no contexts → 422 (departure; a gate that
  requires nothing would fail open).
* **R13. Statuses.** Cap distinct contexts per sha (100, 422 above) besides the 100-row history per context, so the table is
  bounded per commit; the merge gate reads the table directly, never the paged combined view (P#40-41: combined is paged,
  `X-Total-Count` is the full count). A POST without `state` is 422 (H#37 recorded 201: add the departure entry).
* **R14. Gate mechanics.** F4a adds `"Q": {"stop": [5, "expected [201]"]}` to `slice-pending.json` (gating the contents-API
  protection contract Q#0-4 now); F4b derives O's `defer` list by running the scenario (a deferred exchange that passes
  is reported FAIL).

**Contract details F4b must cover** (from Opus's fixture pass): PR create is allowed unless head sha equals base sha (G#35,
T#5, T#9: contained or same-tree heads still get 201); 422 text `Invalid PullRequest: There are no changes between the head
and the base`; PR object keys `additions`, `deletions`, `merge_base`, `comments`, `review_comments`; review POST answers
200; other users' PENDING reviews are hidden from lists but counted in `X-Total-Count`; `official` follows the recorded
transitions (F#28 vs F#33), computed at read time; list `sort=oldest|newest|recentupdate` and `Link` headers (P#0-4,
P#16-18).
