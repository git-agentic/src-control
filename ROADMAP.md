# src-control — Roadmap

This roadmap sequences the phases that build src-control from its current state
(a persistent, branchable, content-addressed VCS with committed secrets) toward
the full thesis: a snapshot-and-tag version control system with **per-file
permissions**, **native committed secrets**, and **in-memory clones**, that
interoperates with Git rather than replacing it wholesale.

Each phase is a vertical slice that ends in something demoable to a real user.
Phases are built **one at a time, systematically**: each gets its own focused
brainstorm → spec (`docs/superpowers/specs/`) → plan (`docs/superpowers/plans/`)
→ implementation, and its roadmap ADR is firmed from **Proposed** to **Accepted**
(with refinements) at that point. The architecture invariants in `CLAUDE.md` hold
across every phase.

## Done

- **Phase 1 — In-RAM virtual worktrees.** Fork N copy-on-write worktrees of a
  repo entirely in RAM with a bounded memory budget + eviction and optional
  spill, leaving zero residual files on disk. (ADR-0005, 0006, 0007.)
- **Phase 2 — Native committed secrets.** Env vars/keys committed into repo state
  as envelope-encrypted objects (per-secret DEK under XChaCha20-Poly1305, DEK
  wrapped per X25519 recipient), decrypted only in an authorized execution
  context and injected into a child process environment. (ADR-0008, 0009, 0010.)
- **Phase 3 — Persistent repo + branches.** A durable `.sc/` repository (loose
  content-addressed objects, named branches, symbolic HEAD, single-writer lock)
  with a git-like working tree and `init`/`commit`/`status`/`log`/`branch`/
  `switch`/`secret`/`run`. Commits and secrets survive across `sc` invocations.
  (ADR-0011.)
- **Phase 4 — Merge & conflict resolution.** `sc merge <branch>` performs
  snapshot-DAG three-way merge, fast-forwards when possible, writes conflict
  markers/sidecars when needed, and records two-parent merge snapshots after
  resolution. (ADR-0012.)
- **Phase 5 — Secret scanner.** Commit-time pattern + entropy scanning
  hard-rejects accidental plaintext secrets, with `sc scan` preview and a
  hash-scoped allowlist. (ADR-0017.)
- **Phase 6 — Remotes.** Local-path `clone`/`fetch`/`push` transfer objects and
  refs, maintain remote-tracking refs, and integrate fetched work through merge.
  (ADR-0013.)
- **Phase 7 — Per-file permissions.** Protected path prefixes encrypt matching
  file content for recipients; unauthorized clones receive ciphertext but skip
  plaintext checkout, while authorized checkout decrypts. (ADR-0014.)
- **Phase 8 — Packfiles + GC.** Sharded/zstd loose objects, pack-aware reads,
  reachability repack/prune, and bulk-pack remote transfer are implemented.
  (ADR-0015.)
- **Phase 9 — Git export / interop.** `sc export --to <git-repo>` writes the
  current branch's full history as Git commits, keeps `gix` quarantined in
  `gitio`, and fails closed on encrypted content unless `--include-encrypted` is
  explicit. (ADR-0016.)
- **Phase 10 — Git as a remote (bidirectional sync).** A local Git repo becomes
  a first-class remote: `sc remote add <name> <git-path> --git`,
  `sc fetch <git-remote>`, and `sc push <git-remote> [--include-encrypted]`
  close the `fetch` → `merge` → `push` loop against Git, via a persisted
  git-oid ↔ sc-id marks map rather than a fatter object model, reusing P9's
  confidentiality gate and P6's fast-forward-only push semantics. Scoped to
  local Git repos on disk; network Git is a later transport swap. (ADR-0018.)
- **Phase 11 — Secret/permission lifecycle (rotation + escrow).** `sc secret
  rotate <name> [--value <new>] [--to <names>] [--identity <key>]` re-seals a
  secret's value under a fresh DEK, composed entirely from existing
  `seal`/`open` primitives (no crypto changes) — closing the true-revocation
  gap ADR-0008/0009 deferred. `sc escrow set/show` configures a single
  break-glass recipient key in `.sc/recipients.toml [escrow]`, auto-appended
  (deduped, forward-only) whenever a secret is sealed or a path is protected.
  `revoke` stays metadata-only, now with a hint pointing at `rotate`. Rotation
  is secrets-only — convergent encryption makes protected-path DEK rotation
  security-meaningless (ADR-0014) — and rotation is a future-reads cutover,
  not erasure: old ciphertext remains reachable from history. (ADR-0019.)
- **Phase 12 — Network transport over SSH.** A framed stdio wire protocol
  mirrors the 8 `Transport` verbs; `sc serve --stdio` dispatches onto the
  existing `LocalTransport` (CAS, pack verification reused verbatim); the
  client spawns the user's `ssh` for `ssh://` remotes, overridable via
  `SC_SSH` (GIT_SSH pattern) so tests and `demo/run_ssh_remote_demo.sh`
  drive the full ssh:// code path with no sshd. Zero new dependencies.
  Accepted limitations: 4 GiB frame cap, no repo paths with spaces over
  real ssh, `sc` must be on the server's PATH. (ADR-0022.)
- **Phase 13 — Agent workspaces (`sc work`).** Fused the two halves of the
  project: fork N in-RAM copy-on-write workspaces from a persistent repo's
  HEAD (the repo's budget-bounded store is the backing tier — eviction is
  safe, no spill backend), materialize each to an ephemeral temp checkout,
  run real agent processes concurrently, and harvest changed workspaces to
  `work-<i>` branches through the commit path (so `.scignore` and the P5
  scanner gate apply). `--with-secrets` injects decrypted secrets into each
  agent's environment via the `sc run` path — one command exercising all
  three thesis pillars. Zero residue outside `.sc/`. (ADR-0023.)
- **Phase 14 — History editing (`sc cherry-pick` / `sc rebase` / `sc undo`).**
  Integrated the agent branches P13 mints: `sc cherry-pick` replays one
  commit onto the current branch (P4-style conflict resolution completed by
  the next commit), `sc rebase` replays a whole branch onto a new base
  (atomic: any conflict aborts with refs untouched — stop-and-continue default
  since P19 (ADR-0029)), and a repo-wide
  operation log made every ref-moving operation undoable (`sc undo`; run
  twice = redo). Replay is P4's three-way merge with base = the picked
  commit's parent — no second merge implementation, no object mutation,
  undo is just moving refs back. Protected content fails closed (lifted in
  P15, ADR-0025), inherited from P4's merge guard. `demo/run_history_demo.sh`
  proves cherry-pick provenance, atomic rebase, and an undo/redo round-trip
  byte-identical at the refs level. (ADR-0024.)
- **Phase 15 — Protected merge & replay.** Lifted the fail-closed guards:
  `sc merge`/`sc rebase`/`sc cherry-pick` work on protected content.
  Id-level cases (unchanged / one side changed / clean deletes) resolve on
  ciphertext ids — sound under convergent encryption — carrying unioned
  wrapped DEKs, with no identity required; only a content-divergent
  protected path needs `--identity` (`ProtectedMergeNeedsIdentity`/
  `NotAuthorized` otherwise). Protection rules merge by union (nothing
  silently unprotects, including re-encrypting a carried PLAIN file that
  matches a landing rule); merged plaintext re-encrypts through the same
  wrap-reuse helper `commit` uses; the secret registry replays through
  rebase/cherry-pick (closing P14's warning — a rules-only or secrets-only
  commit now replays instead of being skipped). Plaintext never enters the
  CAS; conflicted merges/picks persist a decided tree
  (`MERGE_DECIDED_ROOT`/`PICK_DECIDED_ROOT`, HEAD-gated) so completion can
  union rules and carry forward absent protected files without reverting a
  concurrent update. Proven by `demo/run_protected_merge_demo.sh`. (ADR-0025.)
- **Phase 16 — Revocation tombstones.** `(prefix, recipient)` becomes a
  last-writer-wins register (`{key, epoch, state: Granted | Revoked}`);
  merge keeps the higher-epoch entry and resolves epoch ties Revoked
  (fail-closed). The effective recipient set for sealing is Granted entries
  only, closing the ADR-0025 boundary: branch → revoke → merge pre-revoke
  branch now leaves the recipient revoked. Proven by
  `demo/run_revoke_demo.sh`. (ADR-0026.)
- **Phase 17 — Bulk re-wrap + multiple escrow keys.** `sc rewrap
  [--identity <key>] [--dry-run]` re-seals every secret and every protected
  blob's wrap list at the tip to the current recipient/escrow sets, in one
  commit and one oplog record. Secrets are recovered and re-sealed under a
  fresh DEK (P11 rotate machinery); protected blobs get their wrap list
  replaced with exactly `granted_keys() + escrow`, stripping any
  tombstoned recipient's wraps re-attached by a pre-revoke merge (closing
  the ADR-0026 R1 corollary). Skip-and-report: entries the identity can't
  open are skipped and named, the command commits what succeeded, and
  exits non-zero when incomplete. Escrow became a managed list
  (`sc escrow add/remove/show`, `set` kept as replace-with-one sugar);
  `.sc/recipients.toml [escrow]` reads both the old `key` and new `keys`
  form and writes only `keys`. Proven by `demo/run_rewrap_demo.sh`.
  (ADR-0027.)
- **Phase 18 — Network Git remotes.** `sc clone <git-url> <dst>` and
  `sc remote add <name> <url> --git` now reach hosted Git (https/ssh) via
  a lazily-created bare mirror at `.sc/git-remotes/<name>/mirror.git`: the
  spawned system `git` binary is transport-only, and P10's in-process
  `gix` translation, marks map, and confidentiality gate run unchanged
  against the mirror. Auth is fully delegated to `git` (ssh-agent,
  credential helpers, tokens); `sc` has no credential surface. Clone
  routing auto-detects unambiguous git URL forms (https/http, scp-style,
  file://); bare `ssh://` stays sc-native (P12) unless `--git` forces the
  mirror path; `remote add` keeps `--git` required in every case. Proven
  hermetically over `file://` by `demo/run_network_git_demo.sh` (real git
  transport/pack code, no network, no auth); the demo prints the
  real-GitHub recipe (`sc clone git@github.com:… --git` / push visible on
  github.com). (ADR-0028.)
- **Phase 19 — History-editing polish.** `sc amend [-m <msg>]` rebuilds the
  tip commit from the working tree with the tip's own parents kept.
  Stop-and-continue rebase is now the default: a conflict stops with P4
  markers and persisted state rather than aborting the whole rebase;
  `sc rebase --continue [--identity]` completes the conflicted commit and
  resumes the fold (as many stops as needed, still ONE oplog record and
  ONE `sc undo` for the whole operation); `sc rebase --abort` restores the
  pre-rebase tree. `sc cherry-pick --abort` clears pick state and restores
  the untouched tip (no oplog record — no ref ever moved). `sc cherry-pick
  <ref> --mainline <N>` replays a merge commit relative to its Nth parent;
  rebase over a merge-containing range stays refused, now with a hint to
  linearize or drop it. Proven by the extended
  `demo/run_history_demo.sh` (stop/resolve/`--continue`/undo, an aborted
  pick verified byte-identical by checksum, and an `sc amend` message fix
  with history length unchanged). (ADR-0029.)

## Active

- **Phase 20 — Agent sessions + auto-merge.** In build. Spec:
  `docs/superpowers/specs/2026-07-07-p20-agent-sessions-design.md`
  (ADR-0030, Proposed → Accepted at completion).

## Next horizon

P20 is the last phase of this horizon; a new horizon gets brainstormed at
its completion.

## Completed phases (usability-first ordering)

| Phase | Goal | Demoable outcome | ADR |
|-------|------|------------------|-----|
| **P4 — Merge & conflict resolution** | Combine work from two branches | `sc merge <branch>` creates a merge snapshot; clean merges auto-resolve, conflicts are detected and reported | [0012](docs/adr/0012-three-way-merge.md) |
| **P5 — Secret scanner (accidental-plaintext guard)** | Stop plaintext secrets being committed | pattern + entropy scan hard-rejects plaintext secrets, with `sc scan` and a hash-scoped allowlist | [0017](docs/adr/0017-secret-scanner.md) |
| **P6 — Remotes: clone / push / fetch** | Sync a repo between locations | `sc clone <src> <dst>`, `sc push`, `sc fetch` transfer objects + refs; `fetch` then `merge` integrates remote work | [0013](docs/adr/0013-remote-sync-model.md) |
| **P7 — Per-file permissions (encrypted paths)** | Read-confidentiality for designated paths | `sc protect <path> --to …`; an unauthorized clone receives ciphertext it cannot decrypt; authorized checkout decrypts transparently | [0014](docs/adr/0014-per-file-permissions-encrypted-paths.md) |
| **P8 — Packfiles + GC** | Scale storage; reclaim space | `sc gc` packs reachable objects and prunes unreachable loose objects; clone/fetch/push use bulk-pack transfer | [0015](docs/adr/0015-packfiles-and-gc.md) |
| **P9 — Git export / interop** | Round-trip with Git | `sc export --to <git-repo>` writes current-branch history as Git commits; `git log` reads it back | [0016](docs/adr/0016-git-export.md) |
| **P10 — Git as a remote** | Bidirectional sync with Git | `sc remote add <name> <git-path> --git`; `sc push hub` writes commits `git log` can read; a second sc repo `sc fetch hub` + `sc merge hub/main` gets the content back | [0018](docs/adr/0018-git-as-a-remote.md) |
| **P11 — Secret/permission lifecycle** | Cryptographic cutover + break-glass recovery for secrets | `sc secret rotate <name> --value <new>` re-seals under a fresh DEK; `sc escrow set <key>` auto-includes a recovery recipient at `secret add`/`rotate`/`protect` | [0019](docs/adr/0019-secret-lifecycle.md) |
| **P12 — SSH-native network transport** | Sync between machines | `sc clone ssh://host/path`, `sc fetch`/`push` over the wire via `sc serve --stdio`; `demo/run_ssh_remote_demo.sh` proves the round trip with no sshd | [0022](docs/adr/0022-ssh-native-transport.md) |
| **P13 — Agent workspaces** | Parallel agents on a real repo | `sc work --agents 3 -- <cmd>` forks 3 in-RAM workspaces, runs the command in each, harvests to `work-1..3` branches; `sc merge` integrates; zero residue outside `.sc/` | [0023](docs/adr/0023-agent-workspaces.md) |
| **P14 — History editing** | Integrate agent branches; undo anything | `sc cherry-pick work-2`, `sc rebase main`, `sc undo`/redo round-trip proven by `demo/run_history_demo.sh` | [0024](docs/adr/0024-history-editing.md) |
| **P15 — Protected merge & replay** | Confidentiality composes with collaboration | keyless merge of disjoint protected edits; `sc merge --identity` content-merges colliding ones; registry replays through rebase; proven by `demo/run_protected_merge_demo.sh` | [0025](docs/adr/0025-protected-merge-and-replay.md) |
| **P16 — Revocation tombstones** | `sc revoke` durable across merges | branch → revoke → merge pre-revoke branch: recipient stays revoked; proven by `demo/run_revoke_demo.sh` | [0026](docs/adr/0026-revocation-tombstones.md) |
| **P17 — Bulk re-wrap + multiple escrow keys** | org-scale recipient/escrow cutover | change escrow, one `sc rewrap`, every entry re-sealed; R1 wraps stripped; proven by `demo/run_rewrap_demo.sh` | [0027](docs/adr/0027-bulk-rewrap-and-multi-escrow.md) |
| **P18 — Network Git remotes** | fetch/push against hosted Git | `sc clone git@github.com:…` / push visible on github.com; proven hermetically by `demo/run_network_git_demo.sh` | [0028](docs/adr/0028-network-git-remotes.md) |
| **P19 — History-editing polish** | `sc amend`, resumable rebase, pick abort, mainline picks | `sc rebase main` stops on conflict (not aborts), `sc rebase --continue` resumes and lands in ONE oplog record; `sc cherry-pick --abort` restores byte-identical; `sc amend -m` fixes the tip message; proven by the extended `demo/run_history_demo.sh` | [0029](docs/adr/0029-history-editing-polish.md) |

> **Prior art.** Phases P5–P9 adapt decisions from the sibling project
> [git.agentic](https://github.com/git-agentic/git.agentic) (same BLAKE3
> content-addressed substrate): the secret scanner (its ADR-0013), the pluggable
> ObjectStore backend trait (its ADR-0006/0011), object sharding + zstd
> compression, and the destructive-operation approval gate (its ADR-0014). See the
> Cross-cutting principles section.

## Why this order

Usability-first: make src-control a genuinely usable VCS before layering the
remaining differentiators.

- **P4 before P6** so that, once remotes land, `fetch` has a `merge` to feed into
  — the natural collaborative loop (fetch remote work, merge it) works end to end.
- **P5 (secret scanner) early** because it is independent of every other phase,
  cheap, and hardens an already-shipped pillar (Phase 2): it stops *accidental*
  plaintext-secret commits, the natural counterpart to Phase 2's *deliberate*
  encrypted secrets. It blocks nothing and could move earlier or later, but a
  quick safety win slots well right after merge.
- **P6 before P7** so the headline confidentiality demo — *an unauthorized clone
  gets the protected files as ciphertext it cannot decrypt* — is demonstrable the
  moment encrypted paths ship, using the clone built in P6.
- **P7** completes the third thesis pillar (per-file permissions), reusing the
  Phase 2 `scl-crypto` envelope and recipient identities.
- **P8 (GC/packfiles)** is a scaling/operability phase; it also speeds P6's
  transfer, but no earlier phase depends on it, so it slots after the
  feature-bearing phases.
- **P9 (Git export)** is independent interop; it lands last because it serves
  migration/coexistence rather than core capability.
- **P10 (Git as a remote)** follows P9 directly: it reuses P9's deterministic
  export path (now marks-aware) and P9's confidentiality gate, and closes the
  interop loop P9 left one-way. It also reuses P6's remote/fetch/merge/push
  machinery, so it could not land before either P6 or P9.
- **P11 (Secret/permission lifecycle)** follows Phase 2/P7 directly: rotation
  and escrow are pure compositions of the existing `scl-crypto` primitives and
  the Phase 3 commit/registry machinery, with no dependency on P4–P10. It
  slots last chronologically because it hardens already-shipped pillars
  (Phase 2 secrets, P7 paths) rather than adding a new capability axis.
- **P12 (SSH transport)** turns src-control from local-only into a real DVCS;
  it slots after P10 because it generalizes the same Transport seam.
- **P13 (agent workspaces)** closes the original thesis loop: the Phase 1
  in-memory-clone engine finally serves the persistent repos every phase
  since Phase 3 built. It needs nothing beyond Phase 1 + Phase 3 machinery,
  but lands after the transports so harvested branches can travel.

## Dependencies

```
Phase 3 (persistence) ─┬─> P4 Merge
                       ├─> P5 Secret scanner  (independent; hardens Phase 2)
                       ├─> P6 Remotes ──> (fetch feeds P4 merge)
                       ├─> P7 Encrypted paths ── needs P6 clone for the headline demo
                       ├─> P8 Packfiles + GC ── benefits P6 transfer
                       └─> P9 Git export ──> P10 Git as a remote (needs P6 remotes + P9 export)
Phase 6 transport trait ──> P12 SSH-native transport (ADR-0022)
Phase 1 vfs + Phase 3 store ──> P13 Agent workspaces (integrates via P4 merge;
                                composes with P5 scanner, P7 paths, Phase 2 secrets)
scl-crypto (Phase 2) ──> P5 Secret scanner, P7 Encrypted paths
```

All completed phases build on the Phase 3 persistent store. P5 and P7
additionally build on the Phase 2 cryptography. P12 builds on P6's Transport
trait. P13 builds on Phase 1 vfs and Phase 3 store, with composition into P4
merge and optional P5/P7 gates. Otherwise the phases are loosely coupled; the
order above records the path taken to get to the current milestone.

## Cross-cutting principles (adapted from git.agentic)

These apply across phases rather than to one:

- **Pluggable storage/transport seam.** P6 (remotes) and P8 (GC) are designed
  around a single backend trait — `put`/`get`/`has` plus `delete`/`list_prefix`
  and an async variant — with the local filesystem as the default impl and remote
  backends (and managed-Git adapters) behind the same trait. Storage-layer
  concepts never leak into the CLI/API surface. (git.agentic ADR-0006/0011.)
- **Destructive-operation approval gate.** Any operation that can discard work —
  `merge --abort`, `switch` over a dirty tree, future `rollback`/`gc --prune` —
  must either refuse on uncommitted state (today's guards) or require explicit
  confirmation before proceeding. No silent destruction. (git.agentic ADR-0014.)
- **Secret hygiene is layered.** Deliberate secrets are encrypted (Phase 2 / P7);
  accidental plaintext secrets are rejected at `put` time (P5). The two are
  complementary, not alternatives.

## Deferred

Tracked but out of scope for this roadmap horizon (several former entries
graduated into P16–P20 above: revocation tombstones → P16, bulk re-wrap +
multiple escrow keys → P17, network Git remotes → P18, amend/`--continue`/
`--abort`/merge-commit replay → P19, interactive sessions + auto-merge →
P20):

- **HTTP transport** (sc-native). P12 shipped the sc-native SSH transport;
  an HTTP equivalent is a later transport swap on the same seam.
- **Streaming (>4 GiB) wire frames** (P12 caps a frame at 4 GiB).
- **Remaining history-editing depth:** operation objects in the CAS
  (Jujutsu-deep upgrade to the file oplog), oplog entries for
  remote-tracking refs.
- **In-progress guards for the remaining policy ops.** P17's final review
  found (and fixed for `rewrap`) that a policy commit landed mid-merge/pick
  gets its wraps unioned back by the completion — `grant`/`revoke`/`secret
  add/rotate` share this pre-existing gap and should gain the same
  `MergeInProgress`/`PickInProgress`/`RebaseInProgress` guards `rewrap`
  and the ref-movers use. Escalated by P19's final review: an unguarded
  `secret add` mid-stopped-rebase moved the tip and (pre-fix) had its
  commit silently discarded by `--continue` — `rebase_continue` now
  refuses on a moved tip as a backstop, but guarding the ops themselves
  is the durable fix.
- **Rebase/pick abort ergonomics (P19 minors):** aborts silently discard
  the protected-skip list `merge_abort` reports; `sc status` shows stale
  "resolve conflicts" text in the resolved-but-not-continued window; the
  ref-write→state-clear crash window can duplicate an oplog record
  (recoverable; wants a comment). Conflict-materialization block now
  exists in 3 copies (merge/pick/rebase) — extraction candidate.
- **Marks-map staleness recovery.** A rejected non-ff push (or any P10-era
  flow) followed by a `git gc` inside the git repo/mirror can leave marks
  pointing at pruned git objects — a pre-existing P10 staleness class with
  a new P18 trigger (mirror `git gc`). Wants a documented recovery path
  (re-fetch rebuilds, or a marks-verify subcommand). Flagged at the P18
  final review.
- **Sub-tree / partial sharing** and sparse checkouts.
- **Merge ergonomics**: richer conflict resolution UX beyond P4's
  detection/representation.
- **Signed commits / provenance** as a first-class governance feature.

## How a phase gets built

1. Focused brainstorm for the phase (this skill) → phase spec.
2. `writing-plans` → a task-by-task implementation plan.
3. Subagent-driven (or inline) execution with spec + code-quality review per task.
4. Firm the phase's ADR from **Proposed** to **Accepted**, recording any
   refinements discovered during the build.
