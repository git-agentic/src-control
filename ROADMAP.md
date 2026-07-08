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
- **Phase 20 — Agent sessions + auto-merge.** `sc ws fork --agents N
  [--identity <key>]` materializes N durable checkouts under
  `.sc/ws/<i>/` and persists a manifest, surviving across any number of
  `sc` invocations (unlike P13's one-shot `sc work`); `sc ws list`/`run`
  mirror P13's env + secret-injection surface; `sc ws abandon [<i>]`
  drops one or all workspaces with no oplog record. `sc ws harvest
  [--into <branch>] [--identity <key>]` runs each live workspace through
  P13's `harvest_workspace` pipeline, then auto-merges each candidate
  onto the landing branch (default the session's base branch — must be
  the currently-checked-out branch, since the reused merge machinery is
  head-centric) via a read-only conflict probe (`would_merge_cleanly`,
  composing `three_way` + `merge_secrets`) that guarantees no conflict
  markers land unattended: clean merges (including ff) land immediately
  and cumulatively, one oplog record per landing; anything
  conflicted — including protected divergences lacking `--identity` —
  falls back to a collision-suffixed `work-<i>` branch, landing branch
  untouched. A scanner-rejected workspace stays live so the offending
  file can be fixed in place and re-harvested, rather than being
  terminal as in P13. Harvest is a ref-mover guarded by the P19
  merge/pick/rebase-in-progress family; a dirty-tree preflight runs
  before any candidate branch is minted, since there is no CLI command
  to delete a stray one. The session ends (`.sc/ws/` removed, zero
  residue) once no live workspace remains; a crash mid-session leaves
  dirs + manifest intact for the next invocation to resume, and gc roots
  the session's base snapshot gated on manifest presence. Proven by
  `demo/run_ws_demo.sh` (fork/edit/harvest across separate invocations:
  two cumulative clean auto-merges, one conflict fallback, an `sc undo`
  of a landing, zero residue at session end). (ADR-0030.)
- **Phase 21 — Hardening & consolidation.** Closes the P16–P20 review
  tail with no new capability axis. Every commit-creating policy op
  (`protect`/`grant`/`revoke`/`secret add`/`secret rotate`/`secret
  grant`/`secret revoke`) now refuses up front during an in-progress
  merge/pick/rebase, closing the P19-I1 hazard (a review-caught Critical
  found `secret_grant` also needed the guard, alongside `secret_revoke`).
  Marks staleness self-heals at export/push: a mark whose git commit was
  pruned (`git gc` on the target) is re-verified via `GitTarget::
  has_object` and re-synthesized instead of producing a broken parent
  chain, with heal convergence proven to a stable fixed point (a third
  export reports zero stale and zero new marks). `sc rebase --abort`/`sc
  cherry-pick --abort` return and print the protected-skip list
  (`merge_abort` parity); `sc status` distinguishes the resolved-
  awaiting-`--continue` window; multi-stop rebase oplog descriptions
  report cumulative replayed/skipped counts. The three verbatim
  conflict-materialization copies (merge/pick/rebase-fold) collapse into
  one `Repo` helper with zero test edits. `sc ws list` names a landed-
  then-undone workspace truthfully (`"landed (undone by sc undo)"`)
  instead of the misleading generic `"abandoned"`, and no longer
  re-parses the session manifest once per listed workspace. Proven by
  every existing demo staying green plus the pinned regression test for
  each closed finding — a pure-hardening phase ships no new demo script.
  (ADR-0031.)
- **Phase 22 — Signed commits & provenance.** Optional Ed25519 commit
  signatures as content-addressed objects (`TAG_SIGNATURE = 5`, bytes-only
  in `core`), signing the domain-separated snapshot id
  (`"sc-snapshot-sig-v1" || id`) so snapshot ids are untouched and
  retroactive signing is natural. A unified identity v2 (`scl-id-…`) seeds
  both the X25519 encryption key and the Ed25519 signing key via HKDF with
  distinct info strings; v1 `scl-sk-` files keep encrypting but cannot
  sign. Signatures ride existing packs with ZERO wire-protocol changes
  (senders include indexed signatures for the transfer set; receivers
  index `TAG_SIGNATURE` arrivals and dedup idempotently — a review-caught
  Critical fixed retroactive signatures failing to propagate on refetch),
  a gc-rooted `.sc/signatures` index prunes signatures of dead snapshots,
  and git export drops them with a count. `sc verify [--require]` walks
  all parents reporting four distinct states (trusted ✓ / untrusted ? /
  INVALID ✗ / unsigned), `sc log` renders them, and trust policy rides
  `recipients.toml [signing]`/`[signers]`. Signatures defend against
  history rewriting, not trusted-signer misuse or code quality. Proven by
  `demo/run_provenance_demo.sh` (a clone-rewrite attack `sc verify`
  catches while the original stays clean). (ADR-0032.)
- **Phase 23 — Merge ergonomics.** One `conflict_versions(path) -> {base,
  ours, theirs}` re-derives the three versions straight from the DAG for
  whichever op is active (merge/pick/rebase-stop) rather than requiring a
  caller to hand-parse marker text; each side decrypts against its own
  snapshot's protection registry, and the conflict kind (text/binary/
  protected) is classified from tree-entry perms with no decryption
  needed. `sc conflicts [<path>] [--identity]` lists conflicted paths with
  their kind, or shows one path's base/ours/theirs (plaintext for
  protected paths under `--identity`); `sc resolve --ours|--theirs
  <path…> [--identity]` writes the chosen side to the working file, drops
  the `.theirs` sidecar this system may have written (only when it's not
  itself a tracked file — the earlier three-name blind-unlink was a
  reviewer-caught data-loss risk), and clears the path from the active
  conflict record; resolution only decrypts, never re-encrypts, so
  plaintext still never enters the CAS until the unchanged `sc commit`/
  `sc rebase --continue` completion re-encrypts through the same helpers
  `commit` always used. `sc status` gains the same per-path detail under
  every in-progress banner (merge, pick, stopped rebase), and `sc status
  --json`'s `"conflicts"` field is now `[{path, kind}]` instead of a bare
  path list — a strict superset, no existing consumer broke. Proven by
  `demo/run_merge_ergonomics_demo.sh` (a text conflict resolved end-to-end
  with no hand-edited markers, then a protected variant where both the
  base/ours/theirs view and the resolution decrypt under `--identity`).
  (ADR-0033.)
- **Phase 24 — Sparse checkouts / sub-tree sharing.** `.sc/sparse` is a
  local, uncommitted prefix spec (`sc sparse set <prefix…>`/`sc sparse
  show`/`sc sparse disable`); an empty spec is full materialization. The
  whole feature is one generalized predicate: `commit`'s existing
  absent-path carry (the ADR-0025 P15 discipline) widens from "absent AND
  still-protected-and-not-a-recipient" to "absent AND (that OR outside the
  sparse set)," so an out-of-sparse subtree is carried forward
  byte-identical while an in-sparse absence is a genuine deletion;
  `materialize` filters both its write and old-root-removal loops the same
  way, so `sc sparse set`/`disable` re-lay the working tree by narrowing or
  widening on top of the same mechanism. A clean merge/pick/rebase change
  to an out-of-sparse path lands in the CAS without materializing; a
  CONFLICT there refuses with a widen hint instead of auto-materializing.
  `sc ws` workspaces inherit the host's sparse view. Proven by
  `demo/run_sparse_demo.sh` (three subtrees, one narrowed in, edited and
  committed under sparse, then both `sc sparse disable` and an independent
  full clone restore the other two byte-identical). (ADR-0034.)

## Active

None — the P21–P24 horizon is complete; brainstorm the next horizon.

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
| **P20 — Agent sessions + auto-merge** | Multi-invocation agent sessions with hands-off integration | `sc ws fork --agents N`, edit across separate invocations, `sc ws harvest` auto-merges clean results cumulatively and falls back to `work-<i>` on conflict; proven by `demo/run_ws_demo.sh` | [0030](docs/adr/0030-agent-sessions-and-automerge.md) |
| **P21 — Hardening & consolidation** | Close the P16–P20 review tail before new capability work | policy ops refuse during in-progress merge/pick/rebase; a pruned git commit behind a stale mark self-heals on push; rebase/pick aborts report the protected-skip list; `sc ws list` names an undone landing truthfully; every existing demo stays green plus new pinned regression tests | [0031](docs/adr/0031-hardening-consolidation.md) |
| **P22 — Signed commits & provenance** | Detect history rewriting; attribute commits to an identity | `sc keygen` v2 identities (X25519 + Ed25519 from one seed), `sc commit --sign`/`sc sign <ref>`, `sc log` four-state markers, `sc verify --require`; signatures ride existing packs with zero wire changes; proven by `demo/run_provenance_demo.sh` (rewrite attack caught in a clone while the original stays clean) | [0032](docs/adr/0032-signed-commits-provenance.md) |
| **P23 — Merge ergonomics** | Resolve conflicts without hand-editing markers | `sc conflicts [<path>]` lists/shows base-ours-theirs (decrypted under `--identity` for protected paths); `sc resolve --ours\|--theirs <path>` writes clean content; proven by `demo/run_merge_ergonomics_demo.sh` (text + protected conflicts resolved end-to-end) | [0033](docs/adr/0033-merge-ergonomics.md) |
| **P24 — Sparse checkouts / sub-tree sharing** | Materialize one subtree of a large repo, leave the rest on the CAS | `sc sparse set <prefix…>`/`show`/`disable`; `commit`'s absent-path carry widens to out-of-sparse paths (byte-identical carried subtrees); `materialize` filters both its write and removal loops; proven by `demo/run_sparse_demo.sh` (narrow, edit, commit, then disable/clone restore byte-identical) | [0034](docs/adr/0034-sparse-checkouts.md) |

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

Tracked but out of scope for this roadmap horizon (former entries have
graduated twice over: revocation tombstones → P16, bulk re-wrap + escrow
keys → P17, network Git remotes → P18, history-editing polish → P19,
sessions + auto-merge → P20; and now policy-op guards + marks recovery +
abort/status minors → P21, signed commits → P22, merge ergonomics → P23,
sparse checkouts → P24):

- **HTTP transport** (sc-native). P12 shipped the sc-native SSH transport;
  an HTTP equivalent is a later transport swap on the same seam.
- **Streaming (>4 GiB) wire frames** (P12 caps a frame at 4 GiB).
- **Remaining history-editing depth:** operation objects in the CAS
  (Jujutsu-deep upgrade to the file oplog), oplog entries for
  remote-tracking refs.
- **Named/multiple concurrent ws sessions** (P20 ships one unnamed
  session per repo) and workspace re-fork/refresh from a newer tip.
- **Network-Git same-remote edge cases** (ADR-0018's re-synthesis
  limitation across different Git repos).
- **Richer trust models** beyond trusted-key lists (delegation, expiry) —
  P22 ships the key-list model.
- **Sidecar-cleanup footgun in `rebase_continue`.** `replay.rs:1059`'s
  sidecar sweep blind-unlinks `{path}.theirs` with neither the
  non-text-kind gate nor the tracked-path guard that P23 added to
  `resolve_path` — so completing a stopped rebase can delete an untracked
  user file named `foo.txt.theirs`. Pre-existing (predates P23); flagged
  at the P23 final review as the twin of the resolve fix. Apply the same
  two guards.
- **In-progress guard for the RECEIVING repo on push.**
  `LocalTransport::update_ref` moves a branch tip with only a CAS/ff gate
  and no in-progress check on the receiving side — a push into a repo
  with a stopped merge/pick reproduces the P19-I1 discard shape via a
  remote writer (the stopped rebase has its moved-tip backstop;
  merge/pick completion does not). Pre-existing since P6/P12; flagged at
  the P21 final review as the one gap outside the policy-op class.

## How a phase gets built

1. Focused brainstorm for the phase (this skill) → phase spec.
2. `writing-plans` → a task-by-task implementation plan.
3. Subagent-driven (or inline) execution with spec + code-quality review per task.
4. Firm the phase's ADR from **Proposed** to **Accepted**, recording any
   refinements discovered during the build.
