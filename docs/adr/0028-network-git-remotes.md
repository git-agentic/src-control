# ADR-0028: Network Git remotes via a system-git mirror bridge

- **Status:** Accepted
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

## Refinements discovered during the build

- **Clone routing was user-adjudicated mid-build, narrowing the spec's
  original `--git`-always rule for `remote add`.** `sc clone <url> <dst>`
  auto-detects unambiguous git URL forms — `https://`, `http://`,
  scp-style `git@host:path`, and `file://` — none of which can ever mean
  an sc-native remote, so no flag is needed for them
  (`run_clone`/`is_network_git_url` in `crates/cli/src/main.rs`). Bare
  `ssh://` stays sc-native by default (ADR-0022/P12); `sc clone
  ssh://… --git` forces the git-mirror path for an `ssh://` git host.
  `sc remote add <name> <url> --git` is unchanged from the spec: `--git`
  stays required there in every case, including network forms, because
  `remote add` has no clone-time ambiguity to resolve automatically.
- **A Critical, found in review, on the mirror ref's meaning as a
  fast-forward gate.** `export_branch` (P9/P10, reused verbatim) advances
  the *mirror's* git ref, not the network's. Before the fix, `run_push_git`
  treated "mirror ref already matches `local_tip`" as "nothing to push" and
  returned early — so a `mirror_push` that failed after a prior
  `export_branch` had already advanced the mirror left the commit stranded
  on the mirror only, and the next `sc push` reported "already up to date"
  without retrying the network leg. The fix (`crates/cli/src/main.rs`,
  `run_push_git`): for network remotes, `mirror_push` now always runs
  before either early-return or success output, including the
  already-up-to-date branch of the ff-gate — the mirror ref means
  "last-fetched-or-locally-exported state," not "confirmed network state,"
  and only git's own no-op (when the network genuinely already has the
  commit) is allowed to skip the transport call. Regression test:
  `network_push_failure_is_retryable` (`crates/cli/src/main.rs`), which
  reproduces the stranded-push scenario — fails `mirror_push` once via an
  `SC_GIT` shim after `export_branch` has already advanced the mirror, then
  confirms a retried `sc push` still attempts and completes the network
  leg rather than reporting up to date.
- **The bridge is a single new file, not a new crate.** All spawn/transport
  logic lives in `crates/gitio/src/bridge.rs` — `is_network_git_url`,
  `ensure_mirror`, `mirror_fetch`, `mirror_push`, `remote_default_branch` —
  keeping `gix` (in-process translation) and the spawned `git` binary
  (transport) in the same crate but distinct functions, per the ADR-0007
  quarantine. `SC_GIT` overrides the spawned binary (the ADR-0022 `SC_SSH`
  pattern); bridge tests share a `GIT_ENV_LOCK` mutex to serialize
  `SC_GIT` env mutation across `#[test]` threads, since the env var is
  process-global.
- **`file://` classifies as network on purpose**, alongside https/http/scp/
  `ssh://` (`is_network_git_url`). It is not a network protocol, but
  routing it through the mirror bridge is what lets tests and
  `demo/run_network_git_demo.sh` exercise git's genuine transport/pack
  code path hermetically — no real network, no auth, CI-safe — rather than
  taking a shortcut that would leave the transport leg untested.
- **The mirror sits beside, not inside, P10's marks file** — both under
  `.sc/git-remotes/<name>/`: `mirror.git/` (bridge-owned, reconstructible)
  next to `marks` (P10-owned, carries `git_oid ↔ sc_id` identity).
  `demo/run_network_git_demo.sh` step 6 asserts the split directly: it
  deletes `.sc/git-remotes/origin/mirror.git`, confirms `marks` still
  exists, runs `sc fetch`, and confirms the mirror is transparently
  reconstructed — deleting the mirror is always safe; deleting the marks
  map would lose identity across the two DAGs and is never exercised as a
  safe path.
