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

- **Language:** Rust, toolchain pinned to 1.96.1 (`rust-toolchain.toml`, `rust-version`,
  and CI use the same tag; bump all three together). Rationale in ARCHITECTURE.md ("Why Rust").
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
{vfs, crypto} → core` (`gitio → core` is linked by `cli`, never by `repo`), with the separate leaf edges `repo → tlsio`
**and `repo → objio`** (`tlsio` and `objio` are leaves — each depends on no
other workspace crate, not even `core`). **`core` must never depend on Git,
worktrees, or crypto.** **`gix` must stay quarantined in `gitio`** — if you
find yourself reaching for `gix` elsewhere, add a function to `gitio`
instead. **RustCrypto must stay quarantined in `crypto`** — if you find
yourself reaching for it elsewhere, add a function to `crypto` instead.
**rustls/rcgen must stay quarantined in `tlsio`** — if you find yourself
reaching for TLS elsewhere, add a function to `tlsio` instead. **Object-store
SDKs must stay quarantined in `objio`** — if you find yourself reaching for
S3 elsewhere, add a function to `objio` instead. **`repo` must not depend on
`gitio`** — `cli` links both and passes imported snapshots down; `repo` stays
Git-agnostic.

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

All 36 phases, P37a, P37b-i, P37b-ii, P37c and P37d are built and tested. One line of current fact per phase; the
authoritative rationale and full semantics live in the linked ADR, the design
in `ARCHITECTURE.md`. The old per-phase narrative log this table replaced is
archived verbatim at `docs/archive/claude-md-phase-log-2026-07.md` — do not
treat the archive as current; where it disagrees with this file, the ADRs, or
the code, those win.

| Phase | Current state | ADR |
|---|---|---|
| P1 | In-RAM copy-on-write virtual worktrees; bounded blob budget + LRU eviction, optional spill; zero disk residue | [0005](docs/adr/0005-in-ram-vfs-over-fuse.md), [0006](docs/adr/0006-memory-budget-and-eviction.md) |
| P2 | Committed secrets: per-secret DEK (XChaCha20-Poly1305) wrapped per X25519 recipient; secrets are env vars, never files — `checkout` never materializes them; `sc run` injects into a child env, or onto a descriptor with `--secrets-fd N` (unix) | [0008](docs/adr/0008-committed-secrets-envelope-encryption.md), [0009](docs/adr/0009-key-management-and-authorization.md), [0010](docs/adr/0010-secret-registry-and-opaque-wrapped-dek.md), [0052](docs/adr/0052-secret-injection-by-fd.md) |
| P3 | Persistent `.sc/` repo: loose objects, branches, symbolic HEAD, single-writer lock, working tree; write-out paths restore the recorded executable bit (unix; #242; special bits are always cleared, `sc resolve` restores the chosen side's mode, and a swallowed chmod warns once; #243) | [0011](docs/adr/0011-persistent-store-and-working-tree.md) |
| P4 | Snapshot-DAG three-way merge; ff when possible; conflict markers + `.theirs` sidecars | [0012](docs/adr/0012-three-way-merge.md) |
| P5 | Commit-time secret scanner (pattern + entropy) hard-rejects plaintext secrets; `sc scan` preview; hash-scoped allowlist | [0017](docs/adr/0017-secret-scanner.md) |
| P6 | Local-path remotes: `clone`/`fetch`/`push`, remote-tracking refs, `Transport` trait | [0013](docs/adr/0013-remote-sync-model.md) |
| P7 | Protected paths: per-file encryption to a recipient set; unauthorized clones get ciphertext (sealing is randomized since P33) | [0014](docs/adr/0014-per-file-permissions-encrypted-paths.md) |
| P8 | Packfiles + sharded/zstd loose objects; `sc gc` reachability repack + grace-window prune; bulk-pack transfer | [0015](docs/adr/0015-packfiles-and-gc.md) |
| P9 | `sc export --to <git-repo>`: full branch history to Git objects; fails closed on encrypted content unless `--include-encrypted` | [0016](docs/adr/0016-git-export.md) |
| P10 | Local Git repo as a first-class remote via a persisted `git_oid ↔ sc_id` marks map | [0018](docs/adr/0018-git-as-a-remote.md) |
| P11 | `sc secret rotate` (fresh DEK) + escrow keys; rotation ≠ erasure (old ciphertext stays in history) | [0019](docs/adr/0019-secret-lifecycle.md) |
| P12 | ssh:// transport: framed stdio wire protocol, `sc serve --stdio`, client spawns `ssh` (`SC_SSH` overrides) | [0022](docs/adr/0022-ssh-native-transport.md) |
| P13 | `sc work --agents N [--name <base>]`: one-shot in-RAM agent workspaces, harvested to flat `<base>-<i>` branches (default `work`) | [0023](docs/adr/0023-agent-workspaces.md) |
| P14 | History editing: `cherry-pick`/`rebase` as replay; append-only `.sc/oplog`; `sc undo` (twice = redo) | [0024](docs/adr/0024-history-editing.md) |
| P15 | Protected merge/replay: ciphertext-id fast paths; `--identity` only for content-divergent protected paths; rules merge by union; secret registry replays | [0025](docs/adr/0025-protected-merge-and-replay.md) |
| P16 | Durable revocation: per-recipient epoch LWW tombstones; epoch tie resolves Revoked (fail-closed); snapshot tag 4 | [0026](docs/adr/0026-revocation-tombstones.md) |
| P17 | `sc rewrap`: one-commit bulk cutover of secrets + protected wrap lists to current recipients/escrow; escrow is a managed list; `--rotate` also re-seals every protected blob under a fresh key | [0027](docs/adr/0027-bulk-rewrap-and-multi-escrow.md), [0051](docs/adr/0051-rotate-protected-paths.md) |
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
| P28 | Security hardening: a max object size (default 256 MiB; `--max-object-size` / `SC_MAX_OBJECT_SIZE`, 2 MiB to 1 GiB) caps every untrusted transfer length; strict ref-name validation | [0039](docs/adr/0039-security-hardening-sweep.md) |
| P29 | `sc serve --http` access control: bearer tokens (`sc serve token add [--expires]`/`rotate`/`remove`/`list`; an expired token gets the same 401 as an unknown one), `--read-only`, fail-closed non-loopback bind gate | [0040](docs/adr/0040-sc-http-access-control.md) |
| P30 | Sealed agent-session transcripts: `sc transcript attach/show/list/sign/drop`, always-encrypted body, gc-coupled index; `--no-transcripts` on fetch/clone/push (client-side, per command); drop = grow-only tombstone (a bare `Transcript` object, no wire change), kept by gc, hides the body from fetch/reindex | [0038](docs/adr/0038-agent-session-transcripts.md) |
| P31 | Listener resource limits: `--max-connections`, `--timeout`, `--max-pack-size` (both transports), capped read-only drain, accept backoff; later `--max-conn-bytes` per-connection write budget (#233) | [0041](docs/adr/0041-listener-resource-limits.md) |
| P32 | In-binary TLS: `sc+https://` via leaf crate `tlsio`; accept-new TOFU pinning (`sc tls list/forget/pin/path` manages the pin file); `SC_HTTPS_CA_FILE`/`SC_HTTPS_CA=system` validate against a CA instead; client connect/handshake bounded; public plaintext bind no longer justified by tokens alone | [0042](docs/adr/0042-in-binary-tls-sc-https.md), [0053](docs/adr/0053-tls-pin-management.md), [0054](docs/adr/0054-tls-ca-validation.md) |
| P33 | Randomized protected sealing (fresh DEK + nonce; `RANDOMIZED` perms bit); dual-read of pre-P33 convergent ciphertext; per-checkout keyed stat cache; `sc rewrap` upgrades convergent blobs at the tip | [0043](docs/adr/0043-randomized-protected-encryption.md) |
| P34 | Private branches: ref points at a sealed-branch manifest; every commit/tree/blob individually sealed (copy-on-write) under a per-branch KEK wrapped per recipient + escrow; `sc branch --private/grant/revoke/publish`; opaque to non-recipients (content, paths, messages); grant O(1), revoke rotates the KEK; publish replays to public with a scanner gate; git bridge + private→public integration refused; `PROTOCOL_VERSION` 4 | [0044](docs/adr/0044-per-branch-access-control.md) |
| P35 | Native Tauri desktop browser: opens `.sc` repositories through `scl-repo`, shows local/remote refs, all-parent snapshot DAG + provenance, public trees and first-parent diffs; protected content is locked and private branches remain opaque; no mutation or identity surface | [0045](docs/adr/0045-native-desktop-read-model.md) |
| P36 | Bucket WAL remotes (sc+wal://, sc+s3://): immutable packs + CAS'd manifest, checkpoints + log-tail cold start, bucket-backed `sc serve --store` with disposable instances; `get_pack` serves signatures, transcripts and signed drop tombstones by decoding the on-chain packs (#229, no format change); `sc remote compact <name> [--dry-run] [--prune-expire 24h]` (#216) merges small packs behind one manifest CAS, then deletes log entries, checkpoints and unreferenced packs behind an aged-checkpoint cutoff, readers restart on a moved manifest, no format or wire change | [0046](docs/adr/0046-wal-bucket-remotes.md), [0055](docs/adr/0055-bucket-compaction.md) |
| P37a | Want-by-id fetch: batched `GetObjects` verb (wire v5), opt-in `.sc/promisor-lazy`, `sc cat <ref>:<path>` fills only the absent trees and blob on its path; `Store::get` stays network-free; sealed objects refused by kind; sparse widen and the lifted P27 refusals are P37b | [0047](docs/adr/0047-want-by-id-fetch-and-gap-fill.md) |
| P37b-i | Presence-based partial clones: push, verify and gc walk what the store holds (`reachable_objects_partial`), not the fetch filter; push checks every gap id against the destination before sending; a view gap fails with `GapInView` before any write (preflight at the top of `materialize`, plus `undo` and `sparse set`); a partial clone fetches from its origin only. 37b-ii: on a lazy, online clone `ensure_view` fills the view closure by id before switch, fast-forward, undo and `sparse set`, `sparse set` may widen past the filter, a by-id reply is capped at `min(--max-pack-size, 2 GiB)` (a constant since #213, independent of the object cap) and a refused batch is split. | [0048](docs/adr/0048-presence-based-partial-clones.md) |
| P37c | Merge, cherry-pick and rebase on a partial clone: a tree-recursive engine (`merge_trees`) carries a subtree by id when the sides agree and no protection rule applies, reads only where they differ or a rule intersects, and on a lazy, online clone fills what it asks for by id outside the store lock (a non-lazy clone gets the gap error with `sc backfill <path>`); a carried protected subtree keeps the complete input wrap union; a conflict inside the view is marked and resolved like on a full clone (`sc conflicts`/`sc resolve`/`merge --abort`/`sc commit`; the out-of-view part is grafted from the decided root), while a conflict outside the view, or a result that must be sealed outside it, is refused before any ref, merge-state or working-tree change (fetched objects stay). A subtree identical on all three sides is carried even under a protection rule. Cherry-pick and rebase use the same engine (`replay_commit`): the fold's accumulator may hold absent subtrees, the view is filled before the final write, and a stopped pick or rebase keeps its carried subtrees in the decided root. Mode-only edits now merge and a file/directory collision fails before any write, on full clones too. | [0049](docs/adr/0049-merge-on-partial-clones.md) |
| P37d | Agent sessions on a partial clone: `sc ws fork`/`run`/`harvest`/`abandon` and `sc work` work; a workspace or agent sees the host's sparse view only (`sc work` no longer gets a complete tree there), the view closure is filled (lazy, online) or refused with the gap error before anything is written, a workspace commit grafts the out-of-view subtrees from the base without reading them, and harvest lands through the ADR-0049 merge (any conflict falls back to a `work-<i>` branch as on a full clone) | [0050](docs/adr/0050-sessions-on-partial-clones.md) |

## Standing boundaries & gotchas

Cross-cutting current facts that bite. Security boundaries are consolidated in
`docs/THREAT-MODEL.md` — read it before touching anything crypto- or
transport-adjacent. The rest, imperatively:

- **Wire protocol is version 5** (bumped from 4 in P37 for the additive
  `GetObjects` verb; 3 to 4 in P34 for the sealed-branch object kinds). The max object size (`scl_core::max_object_size()`, default 256 MiB;
  `sc serve --max-object-size` and `SC_MAX_OBJECT_SIZE` set it, range 2 MiB to
  1 GiB, out of range aborts startup, ADR-0039 addendum) guards the
  transfer path only — a larger blob commits locally but fails every
  subsequent push/fetch/clone at the receiver. There is no negotiation: each
  receiver applies its own cap, so it must admit the objects it receives. Never inline a size in a new length guard; read the accessor.
- **Writes are budgeted per connection (#233).** `sc serve --max-conn-bytes`
  (default `--max-pack-size` plus the max object size; must be > 0 and at least
  both) counts `PutObject` bytes (structural objects included, `blob_size` 0 or
  not) and, per `PutPack`, the larger of its spool bytes and the decoded bytes
  held (structural records; every record on a `--store` bucket); the default
  (~16.25 GiB) does not bound RAM, lower it with `--max-pack-size`; exceeding it replies `ConnectionBudgetExceeded` (`EC_BUDGET`, no
  version bump) and closes the connection. Reads are not budgeted. A new
  object-write verb must charge `ConnBudget` in `serve_session`.
- **The P35 desktop app is a keyless, read-only top-level adapter.** Its
  renderer has five typed repository commands, no general filesystem/shell
  capability, and no DTO field capable of carrying protected ciphertext or
  identity material.
- **Partial clones refuse `sc export`, `sparse disable`, an empty `sparse set` (and, on a non-lazy clone, one outside the filter), `sc rewrap`,
  `sc grant`/`revoke`, creating, switching to or leaving a private branch, a merge, cherry-pick or rebase whose conflict lies outside the view (a `.theirs` sidecar sits beside its conflicted path, so it is in view whenever that path is; ADR-0049) (no ref, state or working-tree change; on every clone, a conflict stop that needs sealing outside the view is refused the same way), `sc push` to a git remote, and
  `sc fetch` from any native remote but the promisor origin.** `sc merge`, `sc cherry-pick` and `sc rebase` work, including conflicts inside the view (P37c). `sc ws` and `sc work` work too (ADR-0050): workspaces and agents see the clone's view only, and harvest lands through the same merge. `sc backfill --all`
  converts to a genuine full clone and re-enables them. The filter records what
  a clone *asked for*, not what is present: after a fetch an in-filter object
  can be absent. On a lazy, online clone a switch, fast-forward, rebase, undo
  or `sparse set` fetches what its view needs by id first; on a non-lazy or
  offline clone it fails with `GapInView` (nothing changed) and names the
  `sc backfill <prefix>` that repairs it.
- **Bucket remotes hold public content plaintext at rest** — bucket ACL is
  the perimeter (sealed content stays ciphertext, unchanged); partial-clone
  `filter` against bucket remotes is refused.
- **`sc remote compact` deletes bucket objects** (ADR-0055): it needs bucket
  list and delete rights, which pushers and `sc serve --store` instances should
  not hold. It advances the manifest only through the normal CAS (one no-op
  entry plus a checkpoint) and never deletes what the current chain names. Keep `--prune-expire` well above any push's duration (default
  24h): a writer stalled longer than that between uploading a pack and its
  commit can still lose the pack (the leases follow-on closes it).
- **`sc serve --store` still requires a local serve home with `.sc/`** —
  tokens, TLS identity, and pack spills live there; the bucket holds all
  served content.
- **Protected sealing is randomized since P33.** Pre-P33 convergent ciphertext
  dual-reads forever and stays equality-confirmable forever (rotation ≠
  erasure). Identical independent edits on two branches now genuinely
  conflict; identical plaintext at two paths no longer dedups.
- **`sc protect <existing-prefix> --to <new>` does NOT grant the new recipient
  access to already-committed unchanged content** — unchanged files carry
  their prior wrap list. Use `sc grant` (or `sc rewrap`) to add a recipient to
  existing content. Fails safe: under-grants, never over-grants.
- **`sc rewrap` is content-changing when it upgrades** still-convergent blobs
  to randomized, or with `--rotate`; only a plain rewrap over an all-randomized
  tip is policy-only.
- **`.sc/local-key` and the per-checkout protected caches
  (`.sc/protected-cache`, `.sc/ws/cache-<i>`) are never committed and never
  transferred.** Cache saves are best-effort and ordered after ref moves; a
  cache failure may cause a spurious re-seal but never incorrectness. The key
  is owner-only on unix only; non-unix keeps default permissions and warns once
  (#214, ACL deferred).
- **Revoke is standing-only.** A revoked recipient keeps decrypting ciphertext
  sealed before the revoke (they hold the old wraps); cryptographic cutover is
  `sc rewrap --rotate` at the tip (fresh key per protected blob; a plain
  `sc rewrap` only replaces wrap lists) plus rotating the underlying credential.
  History keeps the old ciphertext (rotation is not erasure).
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
  publish`. Merging a public branch IN is allowed (keeps an embargo current);
  its completion re-derives the merge outcome for paths it cannot read from
  disk (out of view, or protected and skipped) instead of carrying the prior
  tip, and under a sparse spec set on the public branch its conflict stop lays
  out in-view files only and refuses an out-of-view conflict before any write (#240; no decided root, it would be unsealed).
  A stopped private merge records `.sc/CONFLICT_PLAINTEXT` and
  `.sc/CONFLICT_SIDECARS` like the public stop (completion leaves sidecars out of
  the sealed tree and removes them), and `merge --abort` needs `--identity` (a
  keyless or non-recipient abort refuses, leaving the stop intact) and restores
  the private tip's checkout (#246).
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
  `sc run --secrets-fd N` (ADR-0052, unix) keeps the secrets out of the
  environment (they arrive on fd N as NUL-terminated `NAME=VALUE` records,
  `SC_SECRETS_FD` names it): hygiene against env dumps and inheritance, still
  not isolation. `sc ws run` and `sc work --with-secrets` use the environment.
- **Sparse is checkout-only** (a spec set on a public branch still applies on a
  private one, where `sparse set` is refused), and a stopped merge/pick/rebase writes no
  conflict marker or sealing-input plaintext outside the view: an out-of-sparse
  conflicted path or sealing input refuses with a `sc sparse set` hint before
  any write (ADR-0034, #210). While a merge/pick/rebase is stopped, `sparse
  set` accepts only a strict widen (new spec covers the old; narrowing,
  sideways and `disable` still refuse): it lays out just the newly in-view
  files from the stop's decided root and leaves protected ones absent, so a
  `rebase --continue` refusal is fixed by widening and rerunning it (#224). A
  binary conflict's `<path>.theirs` sidecar sits beside its in-view file and
  may not match a file-exact spec (partial clones check it by its base path);
  completion and abort remove it.
- **`.sc/git-remotes/<name>/marks` carries `git_oid ↔ sc_id` identity —
  deleting it is destructive.** Deleting the sibling `mirror.git` is always
  safe (reconstructed on next use). Stale marks self-heal on push/export.
- **`sc ws harvest` lands on the currently-checked-out branch** (default the
  session's base; `--into` must also be checked out) — it refuses with a
  `sc switch` hint otherwise.
- **A stopped merge/pick/rebase lists the paths it wrote as plaintext in
  `.sc/CONFLICT_PLAINTEXT`.** Protected conflict text never enters the CAS, so no
  tree records it; completion treats a listed path absent from disk as deleted,
  and abort removes listed paths the restored tree does not track as plain files. The `<path>.theirs`
  sidecars it wrote are listed apart in `.sc/CONFLICT_SIDECARS`; abort, `rebase
  --continue` and `sc resolve` remove only those, never a `.theirs` file the stop
  did not write; the completing commit leaves them out of the tree and removes them.
  A stopped-op `sparse set` widen records the files it is writing in
  `.sc/sparse-widen` (local-only like the rest, removed with the spec write or
  the op); abort and completion delete what an interrupted widen laid outside
  the view.
- **A merge, switch, cherry-pick, rebase, undo or sparse-spec change refuses, before any write, to lay a file or
  directory onto an untracked or ignored one** (`refuse_untracked_overwrite`); move it
  away and retry. A directory holding only tracked files is not such a case: a file/directory change at one path crosses switch, undo, abort and `--continue`, and the emptied directories are cleared (#247). `materialize` checks every such directory before its first removal, so a refusal changes nothing and an abort stays retryable; a forward op also refuses a user's empty directory there (it cannot tell it from a husk), while `materialize` itself prunes empty ones. (On a case-insensitive checkout, replacing `foo/a` with a file `Foo` is refused: the check does not follow the case alias. Fail-closed.) On a sparse checkout the same holds for a path the result adds
  outside the view (a later commit would take the user's file instead, #248); there any directory at the path refuses, tracked contents or not.
  Merging into an unborn branch and the conflict stop of a merge into a private branch are not guarded (except that a private stop refuses a `.theirs` sidecar that would land on an existing file).
- **Every ref-moving or commit-creating op (including all secret/protect
  policy ops) is guarded against an in-progress merge/pick/rebase** — finish
  or abort the in-progress op first. A push into a repo with a stopped op is
  refused for that repo's checked-out branch (other branches still accept it).
- **A `sc work`/`ws` session is the only sanctioned ephemeral+persistent mix:**
  temp checkouts are removed on teardown; durable writes go only through the
  normal commit path.

## Follow-ons

Deferred work is tracked in **`ROADMAP.md` → Deferred** (single source of
truth — do not re-list items here); entries that name an issue mirror the open
GitHub issues. Standing entries: named/concurrent `sc ws` sessions (#215),
blob-size clone filters (#217), the non-unix
`.sc/local-key` ACL (#214), transcript-drop delivery gaps (#230), and the open
sparse, private-branch and abort edge cases (#241, #246, #247, #248).

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
