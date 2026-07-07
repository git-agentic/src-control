# ADR-0028: Network Git remotes via a system-git mirror bridge

- **Status:** Proposed
- **Date:** 2026-07-07
- **Builds on:** ADR-0018 (git as a remote), ADR-0016 (git export), ADR-0007 (gix quarantine), ADR-0022 (spawned-transport pattern)
- **Phase:** 18
- **Spec:** `docs/superpowers/specs/2026-07-07-p18-network-git-remotes-design.md`

## Context

ADR-0018 made a local `.git` path a first-class remote via a persisted
marks map and deferred network Git as "a transport swap onto the same
translation core." The deciding constraint, discovered when this phase was
brainstormed: upstream `gix` (pinned 0.85) implements fetch/clone but
**not push** — push has been planned-but-unimplemented in gitoxide for
years and remains so in 2026. A pure in-process network path is therefore
impossible today, which overturns this ADR's earlier draft assumption
(and its earlier rejection of shelling out).

## Decision

A **system-git mirror bridge**. Each git-backed network remote keeps a
lazily-created bare mirror at `.sc/git-remotes/<name>/mirror.git` whose
git-remote `origin` is the real network URL. The spawned system `git`
binary is transport-only: `sc fetch` runs `git fetch --prune` into the
mirror and then P10's unchanged local-git import (in-process `gix`, marks
map, tracking refs); `sc push` runs P10's unchanged export into the
mirror (ff-only, ADR-0016 confidentiality gate verbatim) and then `git
push`. `sc clone <git-url> <dst>` is composition sugar: init + remote add
+ fetch + adopt the mirror's HEAD default branch.

Auth is fully delegated to the spawned `git` (ssh-agent, credential
helpers, tokens); its stderr passes through unmodified, and `sc` has no
credential surface. `sc remote add <name> <url> --git` accepts network
URL forms (`https://…`, scp-style `git@host:path`, `ssh://…`); the
`--git` flag stays required because bare `ssh://` already means an
sc-native remote (ADR-0022). Tests override the binary via `SC_GIT`
(the ADR-0022 `SC_SSH` pattern); integration tests and the demo drive
the REAL git binary over `file://` URLs — genuine transport code,
hermetic, no auth.

The `gix` quarantine holds: all object translation stays in-process in
`crates/gitio`; the git binary never interprets sc state.

## Consequences

- `sc clone git@github.com:org/repo.git`, fetch, merge, push work against
  hosted Git; the demo proves the round trip over `file://` and prints
  the real-GitHub recipe.
- Objects are duplicated in the mirror (disk cost, reconstructible —
  deleting `.sc/git-remotes/<name>/` is safe); one extra process spawn
  per network op; `git` becomes a runtime requirement **for network
  remotes only**.
- Failure semantics: transport failures surface git's stderr and leave no
  partial sc-side state; the marks map survives transport failures.
- **Swap path:** when upstream `gix` ships push, the bridge collapses to
  in-process transport with zero UX change — the mirror is an internal
  detail behind unchanged commands.

## Alternatives considered

- **Pure in-process `gix` network transport** (this ADR's earlier draft):
  impossible today — `gix` cannot push. Remains the eventual destination
  via the swap path.
- **Hybrid (gix fetch + spawned-git push):** two transport mechanisms and
  two auth stories to document and debug, a heavy optional http feature
  tree for fetch, and it still requires the git binary — all cost, half a
  benefit.
- **Defer the phase until gix ships push:** blocks the roadmap's main
  adoption unlock on an external timeline.
- **Shell out to git for everything (translation included):** violates
  ADR-0007's in-process object-interop decision; the bridge deliberately
  confines git to transport.
