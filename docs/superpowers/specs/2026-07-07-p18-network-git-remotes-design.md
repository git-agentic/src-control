# P18 — Network Git remotes: design

**Date:** 2026-07-07
**Status:** Approved
**ADR:** 0028 (Proposed → Accepted when built)
**Horizon:** `2026-07-07-roadmap-horizon-p16-p20-design.md`

## Problem

P10 made a local `.git` path a first-class remote (marks-map translation,
ff-only push, confidentiality gate). Hosted Git — GitHub over https/ssh —
is the largest remaining adoption gap: today `sc` cannot reach it at all.

## Deciding constraint (discovered in this brainstorm)

Upstream `gix` (pinned 0.85) **cannot push**: fetch/clone are implemented,
push is planned-but-unimplemented as of 2026 (gitoxide crate status). A
pure in-process network path is therefore impossible today. This overturns
the Proposed ADR-0028's assumption and its "don't shell out" rejection.

## Decided design: system-git mirror bridge

Each git-backed **network** remote gets a lazily-created bare mirror at
`.sc/git-remotes/<name>/mirror.git`, whose git-remote `origin` is the real
network URL. The spawned system `git` binary is **transport only** — it
moves bytes between the mirror and the network. Everything else is P10's
existing local-git machinery pointed at the mirror: object translation and
refs via in-process `gix` (quarantine intact), the persisted
`git_oid ↔ sc_id` marks map, ff-only push, the P9 confidentiality gate.

```
sc fetch origin
 ├─ spawn: git -C .sc/git-remotes/origin/mirror.git fetch --prune origin
 └─ P10 import: mirror → sc objects + refs/remotes/origin/<branch> + marks

sc push origin [--include-encrypted]
 ├─ P10 export: sc history → mirror (in-process gix, gate verbatim)
 └─ spawn: git -C mirror push origin <branch>
```

### Command surface

- `sc remote add <name> <url> --git` — `<url>` may now be a network form
  (`https://…`, scp-style `git@host:path`, `ssh://…`) in addition to
  P10's local paths. **`--git` stays required and explicit**: bare
  `ssh://` URLs already mean sc-native remotes (P12), so auto-detection
  would be ambiguous. The URL form decides local-path vs. network-mirror
  handling internally.
- `sc fetch <name>` / `sc push <name> [--include-encrypted]` — unchanged
  UX; the mirror hop is invisible except in timing and the mirror dir.
- `sc clone <git-url> <dst>` — new sugar, pure composition: init +
  `remote add origin <url> --git` + fetch + adopt the mirror's `HEAD`
  default branch (the P10 unborn-branch adoption path).
  [Precision (P18 as shipped, user-adjudicated): clone routing
  auto-detects unambiguous git URL forms — `https://`, `http://`,
  scp-style `git@host:path`, `file://` — which can never be sc-native,
  so no flag is needed for them. Bare `ssh://` stays sc-native (P12,
  ADR-0022); `sc clone ssh://… --git` forces the git-mirror path. The
  `remote add` rule above is unchanged: `--git` stays required there.]

### Auth: fully delegated

ssh-agent, `~/.ssh/config`, credential helpers, and tokens all belong to
the spawned `git`. Its stderr passes through unmodified so auth failures
read exactly like git's own. `sc` has **no credential surface** and
stores nothing. If `git` is not on PATH, any network-remote operation
fails up front with a clear error naming the requirement.

### Failure semantics

- Spawned `git` non-zero exit → the sc operation fails with git's stderr
  attached; no partial sc-side state (import/export only runs after the
  transport step succeeds in each direction).
- Push remains ff-only at the sc layer (P10); a rejected non-ff `git
  push` surfaces git's rejection verbatim.
- The mirror is reconstructible state: deleting
  `.sc/git-remotes/<name>/` is safe (next fetch recreates it); the marks
  map lives beside it as today (P10) and is NOT deleted by transport
  failures.

## Testing & demo

- **`SC_GIT` env override** (the P12 `SC_SSH` pattern): tests inject a
  shim git for failure cases — absent binary, auth-failure simulation,
  non-zero exits — with no network.
- **Real git over `file://` URLs** for integration tests and the demo:
  exercises git's genuine transport/pack code hermetically (no network,
  no auth, CI-safe).
- `demo/run_network_git_demo.sh` (self-checking, house style): create a
  bare "hub" repo, `sc clone file://hub` → commit → `sc push` → verify
  with `git log` on the hub → second `sc clone` sees the commit → `sc
  fetch`/`merge` round trip. Ends by printing the real-GitHub recipe
  (`sc remote add origin git@github.com:… --git`).
- Real-GitHub usage documented in CLAUDE.md; not exercised in CI.

## Accepted costs (documented, not hidden)

- **Object duplication** in the mirror (disk, not correctness). `git gc`
  governs the mirror's side; `sc gc` never touches `.sc/git-remotes/`.
- One extra process spawn per network operation.
- **`git` becomes a runtime requirement for network remotes only** —
  local-path git remotes and everything else keep working without it.
- Two-hop fetch/push latency (network → mirror → sc).

## Future swap path

When upstream `gix` ships push, the mirror bridge can collapse to
in-process transport with zero UX change — the mirror is an internal
detail behind the same commands. ADR-0028 records this explicitly.

## Out of scope

sc-native HTTP transport (separate deferred item); network Git protocol
v2 tuning; `sc remote remove`; authentication UI of any kind; smart
mirror pruning (delete the dir to reclaim space).
