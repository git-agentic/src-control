# CLAUDE.md — working guide for src-control

Read this before making changes. It captures what this project is, how it's
structured, and the conventions to keep it coherent over time.

## What this is

A next-gen version control system. Long-term thesis: a snapshot-and-tag model
(Jujutsu-inspired) with per-file permissions, native committed secrets, and
in-memory clones. We are **not** replacing Git wholesale — we build on / interop
with Git where it saves time.

MVP scope is two wedges:
- **Phase 1 (done):** in-memory virtual worktrees for parallel agents, with a
  bounded memory budget + eviction, leaving zero residual files on disk.
- **Phase 2 (built):** native committed secrets via envelope encryption,
  decrypted only in an authorized execution context.

Full design is in `ARCHITECTURE.md`; the rationale behind each major decision is
recorded as an ADR in `docs/adr/`. Keep them in sync when the design changes.

## Stack & tooling

- **Language:** Rust (stable). Rationale in ARCHITECTURE.md ("Why Rust").
- **Desktop:** Tauri v2 + React/TypeScript under `apps/desktop/`; frontend
  dependencies are bundled and remain presentation-only.
- **Edition:** 2021, inherited via `[workspace.package]`.
- **Key deps (pin latest stable; no LTS concept in Rust/crates):**
  `blake3`, `thiserror`, `hex`, `gix` (Git interop only), `clap`, `anyhow`.
  Phase 2 added RustCrypto AEAD (XChaCha20-Poly1305) + X25519 in `crates/crypto`.
- Bump deps with `cargo add`/`cargo update`; do not hand-edit version pins to
  guesses. `gix` must keep its **default features** (it needs the `sha1`
  hashing feature — disabling defaults breaks `gix-hash`).

## Workspace layout & dependency rule

Crate roles are what `ls crates/` + each `Cargo.toml` say; the rules are what
matters. Strict dependency direction: top-level adapters `{cli, desktop} → repo →
{vfs, gitio, crypto} → core`, with the separate leaf edge `repo → tlsio`
(`tlsio` is a leaf — it depends on no other workspace crate, not even `core`).
**`core` must never depend on Git, worktrees, or crypto.** **`gix` must stay
quarantined in `gitio`** — if you find yourself reaching for `gix` elsewhere,
add a function to `gitio` instead. **RustCrypto must stay quarantined in
`crypto`** — if you find yourself reaching for it elsewhere, add a function to
`crypto` instead. **rustls/rcgen must stay quarantined in `tlsio`** — if you
find yourself reaching for TLS elsewhere, add a function to `tlsio` instead.
**`repo` must not depend on `gitio`** — `cli` links both and passes imported
snapshots down; `repo` stays Git-agnostic.

## Core invariants (do not break)

- **Content addressing:** every object's id is `BLAKE3(canonical_encoding)`.
  Encoding is length-prefixed and tree entries are sorted, so the same content
  hashes identically on any machine. If you change the encoding, you change all
  ids — treat it as a format break and update tests.
- **Blobs are `Arc<[u8]>`-shared.** Forking a worktree must not copy file
  content. Don't introduce a code path that deep-copies blob bytes per worktree.
- **Disk invariant is mode-scoped.**
  - *Ephemeral mode* (agents, `sc demo`, `sc secret-demo`): disk is touched only
    by `Worktree::checkout` and the optional spill backend, both removed on
    session teardown. Zero residual files after the session ends — this is the
    whole Phase 1 pitch. Guard it. Verified by `sc demo` and `demo/run_demo.sh`.
  - *Persistent mode* (`sc init` repos): disk writes to `.sc/` by design.
    `.sc/` is user-owned durable state (like `.git/`). Every `Store::put` in
    persistent mode writes to `.sc/objects/`; `switch` materializes the working
    tree; `commit` snapshots it. This is correct and expected behavior.
  The two modes compose in exactly one way: a `sc work` session (P13) is a
  bounded ephemeral session *hosted by* a persistent repo — temp checkouts
  are removed on teardown, and the only durable writes go through the same
  commit path persistent mode already owns. Otherwise a session is either
  ephemeral or persistent, never a mix.
- **Memory budget bounds resident blob bytes.** Trees/snapshots/secrets stay
  resident (small) and are not evicted. Only reconstructible blobs are evictable.
  Dirty overlay writes are pinned in the worktree and never spilled.
- **Without spill, over-budget inserts fail loudly** (`Error::BudgetExceeded`).
  Never silently drop data to stay under budget.

## Conventions

- Every public type/fn gets a doc comment explaining intent, not mechanics.
- Errors: per-crate `thiserror` enums; the CLI uses `anyhow`. Convert with `?`
  (a bare `return some_vfs_result;` won't coerce into `anyhow::Error`).
- Tests live in `#[cfg(test)] mod tests` next to the code. Every new behavior
  ships with a test. Tests that materialize to disk must clean up after
  themselves and assert the path is gone.
- Keep the CLI demo (`sc demo`) honest: it must end by proving zero residue, and
  `demo/run_demo.sh` provides an independent before/after filesystem diff.

## Commands

The full annotated command + demo reference (every `sc` subcommand, flag
semantics, and `demo/*.sh` proof script) lives in the **`sc-cli-reference`
skill** (`.claude/skills/sc-cli-reference/SKILL.md`) — load it before running
or scripting `sc`. The disk-invariant proofs to keep honest:

```sh
cargo run --bin sc -- demo --agents 4        # parallel-agent demo (must prove zero residue)
bash demo/run_demo.sh                        # independent zero-residue before/after diff
```

Set `CARGO_TARGET_DIR` to a path outside this folder to keep `target/` out of
the project tree if desired.

## Capability map (what's built, by phase)

All 35 phases are built and tested. One line of current fact per phase; the
authoritative rationale and full semantics live in the linked ADR, the design
in `ARCHITECTURE.md`. The old per-phase narrative log this table replaced is
archived verbatim at `docs/archive/claude-md-phase-log-2026-07.md` — do not
treat the archive as current; where it disagrees with this file, the ADRs, or
the code, those win.

| Phase | Current state | ADR |
|---|---|---|
| P1 | In-RAM copy-on-write virtual worktrees; bounded blob budget + LRU eviction, optional spill; zero disk residue | [0005](docs/adr/0005-in-ram-vfs-over-fuse.md), [0006](docs/adr/0006-memory-budget-and-eviction.md) |
| P2 | Committed secrets: per-secret DEK (XChaCha20-Poly1305) wrapped per X25519 recipient; secrets are env vars, never files — `checkout` never materializes them; `sc run` injects into a child env | [0008](docs/adr/0008-committed-secrets-envelope-encryption.md), [0009](docs/adr/0009-key-management-and-authorization.md), [0010](docs/adr/0010-secret-registry-and-opaque-wrapped-dek.md) |
| P3 | Persistent `.sc/` repo: loose objects, branches, symbolic HEAD, single-writer lock, working tree | [0011](docs/adr/0011-persistent-store-and-working-tree.md) |
| P4 | Snapshot-DAG three-way merge; ff when possible; conflict markers + `.theirs` sidecars | [0012](docs/adr/0012-three-way-merge.md) |
| P5 | Commit-time secret scanner (pattern + entropy) hard-rejects plaintext secrets; `sc scan` preview; hash-scoped allowlist | [0017](docs/adr/0017-secret-scanner.md) |
| P6 | Local-path remotes: `clone`/`fetch`/`push`, remote-tracking refs, `Transport` trait | [0013](docs/adr/0013-remote-sync-model.md) |
| P7 | Protected paths: per-file encryption to a recipient set; unauthorized clones get ciphertext (sealing is randomized since P33) | [0014](docs/adr/0014-per-file-permissions-encrypted-paths.md) |
| P8 | Packfiles + sharded/zstd loose objects; `sc gc` reachability repack + grace-window prune; bulk-pack transfer | [0015](docs/adr/0015-packfiles-and-gc.md) |
| P9 | `sc export --to <git-repo>`: full branch history to Git objects; fails closed on encrypted content unless `--include-encrypted` | [0016](docs/adr/0016-git-export.md) |
| P10 | Local Git repo as a first-class remote via a persisted `git_oid ↔ sc_id` marks map | [0018](docs/adr/0018-git-as-a-remote.md) |
| P11 | `sc secret rotate` (fresh DEK) + escrow keys; rotation ≠ erasure (old ciphertext stays in history) | [0019](docs/adr/0019-secret-lifecycle.md) |
| P12 | ssh:// transport: framed stdio wire protocol, `sc serve --stdio`, client spawns `ssh` (`SC_SSH` overrides) | [0022](docs/adr/0022-ssh-native-transport.md) |
| P13 | `sc work --agents N`: one-shot in-RAM agent workspaces, harvested to flat `work-<i>` branches | [0023](docs/adr/0023-agent-workspaces.md) |
| P14 | History editing: `cherry-pick`/`rebase` as replay; append-only `.sc/oplog`; `sc undo` (twice = redo) | [0024](docs/adr/0024-history-editing.md) |
| P15 | Protected merge/replay: ciphertext-id fast paths; `--identity` only for content-divergent protected paths; rules merge by union; secret registry replays | [0025](docs/adr/0025-protected-merge-and-replay.md) |
| P16 | Durable revocation: per-recipient epoch LWW tombstones; epoch tie resolves Revoked (fail-closed); snapshot tag 4 | [0026](docs/adr/0026-revocation-tombstones.md) |
| P17 | `sc rewrap`: one-commit bulk cutover of secrets + protected wrap lists to current recipients/escrow; escrow is a managed list | [0027](docs/adr/0027-bulk-rewrap-and-multi-escrow.md) |
| P18 | Hosted Git (GitHub https/ssh) via system-git mirror bridge (`SC_GIT` overrides); auth delegated to git | [0028](docs/adr/0028-network-git-remotes.md) |
| P19 | Resumable rebase (stop → resolve → `--continue`; one oplog record total), `cherry-pick --abort`/`--mainline <N>`, `sc amend` | [0029](docs/adr/0029-history-editing-polish.md) |
| P20 | Durable multi-invocation agent sessions: `sc ws fork/list/run/harvest/abandon` under `.sc/ws/`; harvest auto-merges, conflicts fall back to `work-<i>` | [0030](docs/adr/0030-agent-sessions-and-automerge.md) |
| P21 | Hardening sweep: in-progress guards on all policy ops, git-marks self-heal, abort protected-skip parity, ws `"landed"` status | [0031](docs/adr/0031-hardening-consolidation.md) |
| P22 | Signed commits: v2 identities (one seed → X25519 + Ed25519), signatures as CAS objects, `sc sign`/`sc verify [--require]` | [0032](docs/adr/0032-signed-commits-provenance.md) |
| P23 | `sc conflicts`/`sc resolve --ours\|--theirs`: whole-file conflict resolution without hand-edited markers | [0033](docs/adr/0033-merge-ergonomics.md) |
| P24 | Sparse checkouts: `.sc/sparse` local prefix spec; checkout-only (CAS keeps everything) | [0034](docs/adr/0034-sparse-checkouts.md) |
| P25 | Streaming pack transfer: bounded RAM on both sides, `ST_PACK_CHUNK` frames (`SC_PACK_CHUNK` tunes), two-pass atomic-after-verify ingest | [0035](docs/adr/0035-streaming-transfer.md) |
| P26 | `sc+http://` transport: `sc serve --http`, thread-per-connection, status-line-before-handshake opening | [0036](docs/adr/0036-http-transport.md) |
| P27 | Partial clone: `sc clone --filter <prefix…>`, `.sc/promisor`, `sc backfill [--all]`; wire `PROTOCOL_VERSION` 3 | [0037](docs/adr/0037-partial-clone.md) |
| P28 | Security hardening: `MAX_OBJECT_SIZE` (256 MiB) caps on every untrusted transfer length; strict ref-name validation | [0039](docs/adr/0039-security-hardening-sweep.md) |
| P29 | `sc serve --http` access control: bearer tokens (`sc serve token`), `--read-only`, fail-closed non-loopback bind gate | [0040](docs/adr/0040-sc-http-access-control.md) |
| P30 | Sealed agent-session transcripts: `sc transcript attach/show/list/sign`, always-encrypted body, gc-coupled index | [0038](docs/adr/0038-agent-session-transcripts.md) |
| P31 | Listener resource limits: `--max-connections`, `--timeout`, `--max-pack-size` (both transports), capped read-only drain, accept backoff | [0041](docs/adr/0041-listener-resource-limits.md) |
| P32 | In-binary TLS: `sc+https://` via leaf crate `tlsio`; accept-new TOFU pinning; public plaintext bind no longer justified by tokens alone | [0042](docs/adr/0042-in-binary-tls-sc-https.md) |
| P33 | Randomized protected sealing (fresh DEK + nonce; `RANDOMIZED` perms bit); dual-read of pre-P33 convergent ciphertext; per-checkout keyed stat cache; `sc rewrap` upgrades convergent blobs at the tip | [0043](docs/adr/0043-randomized-protected-encryption.md) |
| P34 | Private branches: ref points at a sealed-branch manifest; every commit/tree/blob individually sealed (copy-on-write) under a per-branch KEK wrapped per recipient + escrow; `sc branch --private/grant/revoke/publish`; opaque to non-recipients (content, paths, messages); grant O(1), revoke rotates the KEK; publish replays to public with a scanner gate; git bridge + private→public integration refused; `PROTOCOL_VERSION` 4 | [0044](docs/adr/0044-per-branch-access-control.md) |
| P35 | Native Tauri desktop browser: opens `.sc` repositories through `scl-repo`, shows local/remote refs, all-parent snapshot DAG + provenance, public trees and first-parent diffs; protected content is locked and private branches remain opaque; no mutation or identity surface | [0045](docs/adr/0045-native-desktop-read-model.md) |

## Standing boundaries & gotchas

Cross-cutting current facts that bite. Security boundaries are consolidated in
`docs/THREAT-MODEL.md` — read it before touching anything crypto- or
transport-adjacent. The rest, imperatively:

- **Wire protocol is version 4** (bumped from 3 in P34 for the two additive
  sealed-branch object kinds). `MAX_OBJECT_SIZE` (256 MiB) guards the
  transfer path only — a larger blob commits locally but fails every
  subsequent push/fetch/clone at the receiver.
- **The P35 desktop app is a keyless, read-only top-level adapter.** Its
  renderer has five typed repository commands, no general filesystem/shell
  capability, and no DTO field capable of carrying protected ciphertext or
  identity material.
- **Partial clones refuse merge, cherry-pick/rebase, `sc ws fork`/`harvest`,
  `sc work`, `sc export`, and `sparse disable`.** `sc backfill --all` converts
  to a genuine full clone and re-enables them.
- **Protected sealing is randomized since P33.** Pre-P33 convergent ciphertext
  dual-reads forever and stays equality-confirmable forever (rotation ≠
  erasure). Identical independent edits on two branches now genuinely
  conflict; identical plaintext at two paths no longer dedups.
- **`sc protect <existing-prefix> --to <new>` does NOT grant the new recipient
  access to already-committed unchanged content** — unchanged files carry
  their prior wrap list. Use `sc grant` (or `sc rewrap`) to add a recipient to
  existing content. Fails safe: under-grants, never over-grants.
- **`sc rewrap` is content-changing when it upgrades** still-convergent blobs
  to randomized; only a rewrap over an all-randomized tip is policy-only.
- **`.sc/local-key` and the per-checkout protected caches
  (`.sc/protected-cache`, `.sc/ws/cache-<i>`) are never committed and never
  transferred.** Cache saves are best-effort and ordered after ref moves; a
  cache failure may cause a spurious re-seal but never incorrectness.
- **Revoke is standing-only.** A revoked recipient keeps decrypting ciphertext
  sealed before the revoke (they hold the old wraps); cryptographic cutover is
  `sc rewrap` at the tip plus rotating the underlying credential.
- **The oplog is local-only** (like a reflog) — it never travels over
  fetch/push/clone. `sc undo` twice = redo; undoing the initial commit is
  refused.
- **Local branch names are flat** — the ref grammar reserves `name/branch` for
  remote-tracking refs. (Private branches obey the same grammar — the demo
  uses `hotfix-CVE-1234`, not `hotfix/CVE-1234`.)
- **Private branches (P34) are the one branch kind whose ref points at a
  manifest, not a snapshot.** They are opaque to non-recipients (content,
  paths, messages, DAG shape); only the branch name, sealed-object count/
  sizes, recipient ids, and public fork point leak. `commit`/`status`/`diff`/
  `log`/`switch` need `--identity`; every snapshot-assuming op (`amend`,
  `protect`, `secret *`, `rewrap`, `sparse *`, `ws`/`work`, `transcript
  attach`, `sign`, creating a child branch) refuses on a private branch; and
  integrating a private branch INTO a public one (merge/cherry-pick/rebase
  from it, or git export/push) is refused everywhere except `sc branch
  publish`. Merging a public branch IN is allowed (keeps an embargo current).
  `sc branch revoke` rotates the KEK but a recipient who already fetched keeps
  the old manifest (rotation ≠ erasure). **Keep identity files outside the
  working tree** — a key committed under a private branch is sealed in and
  vanishes on the next switch.
- **A signature binds identity to a snapshot id, not a branch position.**
  `amend`/`rebase`/`merge` results start unsigned by design — re-sign after
  (`sc sign <ref>`).
- **Secret injection is an authorized local process context, NOT isolation:**
  same-user processes, crash dumps, and shell wrappers can observe the child
  env. The parent's buffer is zeroized; the child's copy cannot be.
- **Sparse is checkout-only** and has one disk-hygiene boundary: an in-sparse
  conflict co-occurring with an out-of-sparse protected/plain clean change can
  leave that out-of-sparse plaintext on disk until the next materializing
  operation re-lays the tree (not data loss, not a new disclosure — ADR-0034).
- **`.sc/git-remotes/<name>/marks` carries `git_oid ↔ sc_id` identity —
  deleting it is destructive.** Deleting the sibling `mirror.git` is always
  safe (reconstructed on next use). Stale marks self-heal on push/export.
- **`sc ws harvest` lands on the currently-checked-out branch** (default the
  session's base; `--into` must also be checked out) — it refuses with a
  `sc switch` hint otherwise.
- **Every ref-moving or commit-creating op (including all secret/protect
  policy ops) is guarded against an in-progress merge/pick/rebase** — finish
  or abort the in-progress op first.
- **A `sc work`/`ws` session is the only sanctioned ephemeral+persistent mix:**
  temp checkouts are removed on teardown; durable writes go only through the
  normal commit path.

## Follow-ons

Deferred work is tracked in **`ROADMAP.md` → Deferred** (single source of
truth — do not re-list items here). Notable standing entries: transparent
lazy-fetch for partial clones, per-case gap-tolerant merge/replay on partial
clones, rotate-for-paths (unlocked by P33, recorded not built), fd/stdin
secret injection, CA-path validation alongside TOFU pinning, and pin-management
UX (`sc tls`).

## Agent skills

Per-repo configuration for the engineering skills (triage, to-tickets,
to-spec, qa, diagnosing-bugs, improve-codebase-architecture, tdd, …).

### Issue tracker

Issues are tracked as **GitHub Issues** on `git-agentic/src-control` via the
`gh` CLI; external PRs are NOT a triage surface. See
`docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary — `needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human`, `wontfix` (each role's label string equals its name). See
`docs/agents/triage-labels.md`.

### Domain docs

**Single-context.** No `CONTEXT.md` yet — domain language lives in
`CLAUDE.md`/`ARCHITECTURE.md`, decisions in the one root `docs/adr/`. See
`docs/agents/domain.md`.
