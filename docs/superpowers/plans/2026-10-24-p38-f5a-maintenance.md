# P38 F5a: maintenance (gc, runtime cleanup)

F5 (ops) is split in two PRs. F5a is the part that deletes data: garbage collection and the cleanup of
what killed git processes leave behind. F5b (logs, drain, bind-gate tests, container image, ops doc) follows.

Not in F5: per-owner byte quotas and per-user transport limits. Engine's clones come from one service
account, so a per-user limit needs a deliberate budget; both stay in #297.

## Problem

Unreferenced objects accumulate: refused or lost contents writes, aborted merge commits, force-pushed
history. `gc.auto=0` is pinned, so nothing ever collects them. A git writer killed at run time (timeout,
cancel) can leave `refs/**/*.lock` or `objects/incoming-*` behind until the next restart's sweep.

## Design

### 1. Where gc runs

Inside the server (the data-directory lock makes an offline CLI impossible). Two triggers, one code path
(`maintenance::run_all`):

- a timer thread: `--maintenance-interval` seconds (default 86400, 0 = off), first run one interval after start;
- `POST /api/v1/admin/cron/{task}` (Gitea route, site admin, `admin` write scope). Task `git_gc_repos` answers
  204 and runs the pass on a background thread; an unknown task is 404; a pass already running is not started
  twice (still 204, as Gitea). Other Gitea task names are 404 (not recorded in the fixtures, Engine does not call them).

One pass at a time, repositories sequentially, `live` rows only.

### 2. What one repository gets (two stages)

Sol's review of the first draft (no gate, `git gc --prune`) found real losses, so collection is split into a
non-destructive stage and a short destructive one under the write gate.

**Stage 1, no gate, deletes nothing:** `git gc --prune=never --force` with
`-c gc.autoDetach=false -c pack.threads=2 -c pack.windowMemory=256m`. With `never`, git packs the reachable
set, loosens unreachable packed objects (keeping the old pack's mtime) and prunes nothing. It runs through the
`Git` runner (admission slot, process group, output cap) with `--gc-timeout` (default 3600 s). The runner sets
no `RLIMIT`s (only transports do); the bound is the timeout, `pack.*` settings and the container's cgroup limits.

**Stage 2, under the repository's write gate (`Lifecycle::with_gate`, gate only, no lifecycle lock):**

1. `pulls::reconcile_repo` runs first and must succeed: it recreates every missing retention ref (open head,
   closed or merged final head, and the new merge-commit ref, below). On any error the repository is skipped
   and logged; nothing is deleted.
2. `git prune --expire=<--gc-prune-expire>` (default 14 days, rejected below `max(2 * --git-timeout, 1 h)`).
   After stage 1 every unreachable object is loose, so `prune` is complete. Holding the gate excludes the API
   writers (contents write, merge, PR sync), the producers that copy existing, possibly old, objects into new
   trees (`gitwrite.rs` `mktree`) and so could otherwise reference an object that prune is about to unlink.
   A push cannot do that: receive-pack's objects arrive fresh, and its connectivity check needs objects
   reachable from existing refs. Left over, and documented in the threat model: a push built on a commit that a
   concurrent force-push has just unreferenced, whose objects are all older than the window, while stage 2 runs.
3. Runtime cleanup (below), then the gate is released.

A writer that arrives during stage 2 waits on the gate (its normal 10 s) and answers 503 only if prune outlasts it.
Stage 2 is a reachability walk (commit-graph backed) plus a scan of the loose objects, so it is far shorter than stage 1.
Stage 1 is concurrent-safe in git itself (`pack-refs`, `repack -d` take their own locks, readers re-scan packs).

- **`--force`** because a `gc.pid` left by a killed gc must not block the repository forever; only this module
  runs gc, one run per repository at a time (a per-repository `AtomicBool`).
- **Delete safety.** `Spec` gains `cancel: Option<&Cancel>`, polled by the runner's wait loop (new
  `GitError::Cancelled`, group killed and reaped as for a timeout). Both stages run under one
  `Registry::register` registration (liveness checked by a direct database read, as `cgi.rs` does, never by a
  lifecycle lock inside the registry callback), held through every filesystem operation including cleanup, so
  `delete` (which takes the exclusive lifecycle lock, then closes the slot and waits) cancels the run and waits
  for it before the rename. The run never takes the lifecycle lock, and releases the registration before any
  follow-up that does. A cancelled run starts no further command or cleanup. Shutdown cancels it.
- **Free space.** Skip stage 1 (logged) when `free < min_free + repository size` (`repack` writes the new pack
  before it removes the old ones); size is `size-pack + size` from `git count-objects -v` (KiB).

### 3. Completed merges keep their merge commit

Sol: after a merge finishes, the landing marker is deleted and only the head is retained, so a later rewrite of
the base orphans the merge commit that `merge_commit_sha` still reports, and gc would delete it. `finish`
therefore writes `refs/forge/pull/<n>/merge` (the merge commit) before retiring the marker, and
`reconcile_repo` recreates it for every merged PR from `merge_commit_sha` and removes `/merge` refs of unknown PRs.
Nothing is deployed from before F4c, so there is no legacy data to backfill.

### 4. Runtime cleanup of stale locks and quarantine directories

Age alone does not prove an owner has ended (wall-clock steps, host suspend), so deletion requires
ownership to be excluded and age is only a second condition:

- the repository's write gate is held (no API writer) and the registry slot has no live registration
  (`Registry::with_idle`, which runs the cleanup under the registry mutex so no transport can register meanwhile;
  it is a few `readdir`/`unlink` calls);
- and the item's mtime is older than 600 s.

Items: `objects/incoming-*` directories; `refs/**/*.lock`, `packed-refs.lock`, `HEAD.lock`. Cleanup runs even
if gc failed (the failure may be caused by such a lock). Startup keeps removing all of them unconditionally
(`orphans::sweep` after it kills orphans) and gains `objects/incoming-*`.

### 4a. Additions after the diff review

- Cleanup also needs the exclusive lifecycle lock (`Lifecycle::try_exclusive`, never waits, taken after the gate): default-branch
  changes and branch deletes write refs under that lock without the gate.
- `pulls::verify_roots` checks every pull request row against the refs after the reconcile (a sync logs and skips a PR it cannot
  repair, so reconcile success alone proved nothing).
- The cancel flag is checked after the gate is taken; the reconcile does not carry it (short commands, a slow delete answers 503).

### 4b. Additions after the Opus review

- git names the quarantine `objects/tmp_objdir-incoming-XXXXXX` (since 2.35), not `incoming-*`; the first cut matched nothing. A test
  pins the prefix against a real push.
- A killed gc leaves `objects/info/commit-graph.lock` (and the chain lock), which fails every later gc: `clean_repo` removes them.
- Stage 1 depends on `gc.cruftPacks=false` (see the threat model). Cleanup runs before stage 1 (a stale `packed-refs.lock` makes gc
  print an error and still exit 0).
- Registrations carry a `writes` flag; fetches do not defer the cleanup. The reconcile holds the shared lifecycle lock (`try_read`).
  A pending merge intent skips the prune. The prune has its own 10-minute limit. `core.packedRefsTimeout` is 5 s so a ref delete
  survives a concurrent `pack-refs`. The reconcile finishes its other repairs when the merge-ref repair fails.
- Stage 2 is not purely file-system work: the reconcile can finalize or abort merge intents and close pull requests.

### 4c. Additions after the second Opus review

- `refs/forge/pull/<n>/base` keeps the stored base commit of unmerged PRs (a commit that is already gone is skipped, not an error).
- The prune is skipped when stage 1 did not complete; duration flags are capped at ten years; the cutoff is checked in the pass too.
- A quarantine is renamed under the registry lock and deleted after it; a gate timeout in the cleanup step no longer skips the repository.
- The plan's `run_all`, per-repository `AtomicBool` and `with_idle` were not built: one runner thread serializes passes, and
  `with_only` replaced `with_idle`.

### 5. Failure and recovery

gc killed at any point: stage 1 leaves the old packs until the new one is complete; git's temp files
(`objects/pack/tmp_*`, `gc.pid`) are removed by the next gc (`--force`, `prune`). Stage 2 deletes only
unreachable, aged loose objects. No database state changes, so nothing needs reconciling. A pass interrupted by
shutdown just ends.

### 6. Tests

Deterministic interleavings come from `SC_FORGE_GIT` pointing at a wrapper script that sleeps on chosen
subcommands (`gc`, `prune`), so a test can hold stage 1 or stage 2 open.

- old unreferenced loose object and old unreferenced packed object: both gone after a pass; young ones stay;
- reachable data stays: branch tips, a merged PR's frozen head, an open PR's retention ref after its head branch
  was deleted, a closed PR's `final_head_sha`, merge markers; `git fsck --strict` clean and a clone of every
  branch succeeds (descendant bytes present, not just refs);
- merge commit survives: merge, force-push the base away from it, backdate the objects, run a pass, the merge
  commit still exists and `GET pulls/{n}` still reports it;
- repair failure skips pruning: delete a retention ref and lock it (`<ref>.lock`), backdate, run a pass; nothing is deleted;
- stage 2 excludes API writers: with `prune` held open by the wrapper a contents write waits on the gate and
  completes after; a write holding the gate delays stage 2 (it never prunes under a running write);
- a transport in flight on the repository defers cleanup (the registry is not idle), a stale lock then goes on
  the next pass; with the age under 600 s a lock stays;
- delete during stage 1 and during stage 2 cancels the run and the delete completes; no run touches the directory afterwards;
- the aborted-merge commit (old) is collected after its journal row is `aborted`;
- startup removes `incoming-*` and locks regardless of age;
- cron route: non-admin 403, token without `admin` scope 403, anonymous 401, unknown task 404, admin 204; a
  second call during a pass starts nothing;
- free-space skip with a huge `--min-free-bytes`; a prune window below the minimum is refused at startup;
- runner: a cancelled `Spec` kills its group (with a grandchild) and returns `Cancelled`.

### 7. Out of scope, recorded

- `refs/forge/*` growth: `gc` packs them.
- An idle repository is gc'd every interval (a clean one is cheap); no `last_gc` state in the database.
- Repository disk usage is not reported by an API; the logs of F5b carry the size before and after each pass.
- Pushes that build on an object older than the window while a force-push unreferences it (see 2).
