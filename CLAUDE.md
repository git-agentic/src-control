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
- **Edition:** 2021, inherited via `[workspace.package]`.
- **Key deps (pin latest stable; no LTS concept in Rust/crates):**
  `blake3`, `thiserror`, `hex`, `gix` (Git interop only), `clap`, `anyhow`.
  Phase 2 added RustCrypto AEAD (XChaCha20-Poly1305) + X25519 in `crates/crypto`.
- Bump deps with `cargo add`/`cargo update`; do not hand-edit version pins to
  guesses. `gix` must keep its **default features** (it needs the `sha1`
  hashing feature — disabling defaults breaks `gix-hash`).

## Workspace layout & dependency rule

```
crates/core   → content-addressed store, object model, budget + eviction
crates/vfs    → in-memory worktree engine (depends on core)
crates/gitio  → Git import via gix (depends on core; ONLY crate that links gix)
crates/crypto → envelope encryption (depends on core; ONLY crate linking RustCrypto)
crates/repo   → persistent .sc/ repo: objects, refs, branches, working tree (depends on core/vfs/crypto)
crates/cli    → `sc` binary (depends on repo + vfs + gitio + crypto + core)
```

Strict dependency direction: `cli → repo → {vfs, gitio, crypto} → core`.
**`core` must never depend on Git, worktrees, or crypto.** **`gix` must stay
quarantined in `gitio`** — if you find yourself reaching for `gix` elsewhere,
add a function to `gitio` instead. **RustCrypto must stay quarantined in
`crypto`** — if you find yourself reaching for it elsewhere, add a function to
`crypto` instead. **`repo` must not depend on `gitio`** — `cli` links both and
passes imported snapshots down; `repo` stays Git-agnostic.

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

```sh
cargo test                                   # whole workspace
cargo run --bin sc -- demo --agents 4        # parallel-agent demo
cargo run --bin sc -- demo --agents 6 --budget-mb 4 --spill   # exercise eviction
cargo run --bin sc -- import --repo <path>   # import a Git repo's HEAD
bash demo/run_demo.sh                         # independent zero-residue proof
cargo run --bin sc -- keygen                 # generate an X25519 identity
cargo run --bin sc -- secret-demo            # committed-secrets authorize/deny/grant proof

# Persistent repo commands (sc init creates .sc/ in the working directory):
cargo run --bin sc -- init                   # initialize a new persistent repo
cargo run --bin sc -- commit -m "msg"        # snapshot working tree as a commit
                                             # honors .scignore at the repo root (gitignore
                                             # subset; hides untracked matches only — tracked
                                             # paths are never ignored)
cargo run --bin sc -- status                 # working-tree changes vs HEAD (--json for scripts)
cargo run --bin sc -- diff                   # line-level unified diff vs HEAD
cargo run --bin sc -- log                    # history: id, date, author, message, (merge) marker
                                             # (--json for scripts; also on secret list)
                                             # commit/merge author: --author > $SC_AUTHOR > OS user
cargo run --bin sc -- branch <name>          # create a new branch at current tip
cargo run --bin sc -- switch <name>          # switch branch + materialize working tree
cargo run --bin sc -- merge <ref> [--identity <key>]   # three-way merge (ff when possible; exits
                                             # 1 on conflicts; --identity only needed when a
                                             # protected path diverged in content on both sides)
cargo run --bin sc -- scan                   # preview the commit-time secret scan
cargo run --bin sc -- clone <src> <dst>      # copy a repo (objects + refs)
cargo run --bin sc -- protect <prefix> --to <recipient>   # encrypt matching paths (P7)
cargo run --bin sc -- grant <prefix> --to <recipient> --identity <key>   # path-protection grant
cargo run --bin sc -- revoke <prefix> --recipient-id <id>                # path-protection revoke
                                             # NB: top-level grant/revoke act on protected
                                             # path prefixes; `secret grant/revoke` act on
                                             # named secrets — two different surfaces
cargo run --bin sc -- secret add <name> --to <recipient> --value <val>
                                             # omit --value to read the secret from stdin
                                             # (keeps it out of `ps` and shell history);
                                             # `secret rotate --value-stdin` likewise
cargo run --bin sc -- secret grant <name> --to <recipient> --identity <key>
cargo run --bin sc -- secret revoke <name> --recipient-id <id>
cargo run --bin sc -- secret list
cargo run --bin sc -- run -- <cmd> [args…]   # inject decrypted secrets + run command
cargo run --bin sc -- gc                      # pack reachable objects + prune unreachable
cargo run --bin sc -- gc --prune-expire 7d    # custom grace window
cargo run --bin sc -- export --to <git-repo>  # write current branch history to Git
cargo run --bin sc -- export --to <git-repo> --include-encrypted  # allow protected ciphertext
bash demo/run_repo_demo.sh                   # end-to-end persistent repo proof
cargo run --bin sc -- remote add <name> <git-path> --git   # register a git-backed remote
cargo run --bin sc -- fetch <git-remote>                    # import git history -> remote-tracking ref
cargo run --bin sc -- push <git-remote> [--include-encrypted]  # export sc history -> git ref (ff-only)
bash demo/run_git_remote_demo.sh                            # git-as-a-remote round-trip proof
cargo run --bin sc -- remote add <name> ssh://[user@]host[:port]/path   # ssh-native remote
cargo run --bin sc -- clone ssh://host/path <dst>   # clone over ssh (spawns `ssh … sc serve --stdio`)
cargo run --bin sc -- serve --stdio <path>          # wire-protocol server (invoked via ssh; not interactive)
bash demo/run_ssh_remote_demo.sh                    # ssh transport round-trip proof (SC_SSH shim, no sshd)
cargo run --bin sc -- secret rotate <name> --value <new>       # re-seal under a fresh DEK
cargo run --bin sc -- secret rotate <name> --identity <key>    # same value, fresh DEK
cargo run --bin sc -- escrow set <pubkey-or-name>              # break-glass recovery key
cargo run --bin sc -- escrow show
bash demo/run_lifecycle_demo.sh                                # rotation + escrow proof
cargo run --bin sc -- work --agents 3 -- <cmd>   # fork agent workspaces, run <cmd> in each,
                                                 # harvest changed ones to work-<i> branches
                                                 # (--with-secrets --identity <key> injects
                                                 # decrypted secrets into each agent env)
bash demo/run_work_demo.sh                       # parallel-agents round-trip proof
cargo run --bin sc -- cherry-pick <ref> [--identity <key>]   # replay one commit onto the
                                              # current branch (--identity as above)
cargo run --bin sc -- rebase <target> [--identity <key>]     # replay current branch onto
                                              # <target> (atomic; conflicts abort with refs
                                              # untouched; --identity as above)
cargo run --bin sc -- undo                    # revert the last operation (again = redo)
cargo run --bin sc -- oplog                   # list recent operations
bash demo/run_history_demo.sh                 # cherry-pick/rebase/undo round-trip proof
bash demo/run_protected_merge_demo.sh         # protected merge & replay proof (P15)
```

Set `CARGO_TARGET_DIR` to a path outside this folder to keep `target/` out of
the project tree if desired.

## Phase 2 is built

`crates/crypto` (`scl-crypto`) exists and owns all cryptography: envelope
encryption (per-secret DEK under XChaCha20-Poly1305, DEK wrapped per recipient
via X25519 ECDH + HKDF-SHA256), keygen, and a `KeyProvider` abstraction for
loading identities. `Snapshot` carries a `secrets: BTreeMap<String, ObjectId>`
side registry (separate from the file tree) so secrets are env vars, not files
— `checkout` never materializes them. An authorized context decrypts the value
in memory and injects it into a child process environment via `run_with_secret`.

The persistent store and standalone `sc secret add`/`sc run` across invocations
are now built (persistent-store branch). Do not weaken Phase 1 or Phase 2
invariants when extending further.

**Phase 8 is built.** Packfiles (`objects/pack/<hash>.pack` + `.idx`),
sharded/zstd loose objects (`objects/<aa>/<rest>`), `sc gc` (reachability repack
+ grace-window prune), and bulk-pack transfer (push/clone/fetch move one pack
instead of object-at-a-time) are all shipped.

**Phase 9 is built.** `sc export --to <git-repo>` maps the current branch's full
history to Git objects (blob/tree/commit), keeps `gix` quarantined in `gitio`,
fails closed on encrypted content (refuse unless `--include-encrypted`; then
protected files export as ciphertext and secrets are dropped), overwrites the
target ref (mirror semantics), auto-inits a bare repo if the path is absent, and
is idempotent via deterministic signature synthesis.

**Phase 10 is built.** A local Git repo is now a first-class remote. `sc remote
add <name> <git-path> --git` registers it; `sc fetch <git-remote>` imports the
full Git history deterministically and writes a `refs/remotes/<name>/<branch>`
tracking ref + a persisted `git_oid ↔ sc_id` marks map
(`.sc/git-remotes/<name>/marks`); `sc push <git-remote> [--include-encrypted]`
synthesizes/reuses Git commits for the current branch and fast-forward-updates
the Git ref, reusing P9's export machinery and confidentiality gate verbatim
(refuse on protected content unless `--include-encrypted`). Identity across the
two DAGs is carried by the marks map, not by a fatter object model — the
content-addressing invariant is unchanged. The git-remote path dispatches above
the P6 `Transport` trait rather than implementing it (a Git remote has a
different id space and encoding than sc's `Transport` assumes). Scope is local
`.git` paths on disk only; network Git is deferred. One accepted MVP
limitation: fetching from Git repo A and pushing a Git-origin commit to a
*different* Git repo B re-synthesizes with dropped committer/timezone/gpgsig
and a different Git oid than A had — same-remote fetch/push stays clean. A side
effect of this phase: `sc merge <ref>` now also fast-forwards into a freshly
initialized (unborn) branch by adopting the incoming snapshot wholesale,
needed because the demo's second repo merges a git-fetched branch into a repo
with no local commits yet. See ADR-0018.

**Phase 11 is built.** `sc secret rotate <name> [--value <new>] [--to <names>]
[--identity <key>]` re-seals a secret's value under a fresh DEK, composed
entirely from existing `seal`/`open` primitives (`crates/crypto` is
unchanged). With `--value`, seals the new plaintext directly; without it,
recovers the current value via `--identity` and re-seals it. Recipients
default to the secret's current set (resolved by reverse `recipient_id`
lookup against `.sc/recipients.toml`) or `--to`. This is secrets-only —
per-file protected paths use convergent encryption, where DEK "rotation" is
either dedup-breaking or security-meaningless, so path lifecycle stays on
recipient re-wrap (`grant`/`revoke`). `sc secret revoke` remains
metadata-only (unchanged behavior), now printing a hint to run `rotate` for
an actual cryptographic cutover. `sc escrow set <pubkey-or-name>` / `sc escrow
show` configure a single break-glass recipient key in `.sc/recipients.toml
[escrow]`, auto-appended (deduped) whenever `secret add`, `secret rotate`, or
`protect` seals/wraps — forward-only (existing secrets/paths gain escrow only
when next rotated/re-wrapped) and policy, not enforcement (nothing stops a
caller from bypassing the CLI and omitting it). **Rotation ≠ erasure:**
content-addressed history means the old ciphertext object remains reachable
and decryptable by anyone who kept the old DEK; rotation cuts off *future*
reads through the current registry, and real security requires rotating the
underlying external credential too. See ADR-0019.

**Phase 12 is built.** sc-native network transport over SSH: a framed stdio
wire protocol mirrors the 8 `Transport` verbs (version handshake, typed
`NonFastForward`/`NotARepo` errors); `sc serve --stdio` dispatches onto the
existing `LocalTransport` (CAS, pack verification reused verbatim); the
client spawns the user's `ssh` for `ssh://` URLs, overridable via `SC_SSH`
(GIT_SSH pattern) — tests and `demo/run_ssh_remote_demo.sh` drive the full
ssh:// code path through a shim with no sshd. Zero new dependencies. Accepted
limitations: 4 GiB frame cap, repo paths with spaces unsupported over real
ssh, `sc` must be on the server's PATH. See ADR-0022.

**Phase 13 is built.** Agent workspaces: `sc work --agents N -- <cmd>` forks
N in-RAM copy-on-write workspaces from HEAD inside the repo's budget-bounded
persistent store (eviction is safe — the store on disk is the reconstruction
source; no spill backend in this path), materializes each to an ephemeral
temp checkout with P7-aware decryption, runs the agent commands concurrently
(`SC_WORKSPACE`/`SC_WORKSPACE_DIR` in env; `--with-secrets --identity <key>`
injects decrypted secrets via the `sc run` path), and harvests each changed
workspace through the full commit pipeline (`.scignore`, P5 scanner gate,
protected-path re-encryption) to a flat `work-<i>` branch — integration is
plain `sc merge`. HEAD, the current branch, and the user's working tree are
never touched; a failed agent's partial work is still harvested; teardown
leaves zero residue outside `.sc/`. Branch names are flat because the ref
grammar reserves `name/branch` for remote-tracking refs. See ADR-0023.

**Phase 14 is built.** History editing: `sc cherry-pick <ref>` and `sc rebase
<target>` are both replay, composed from P4's `three_way_files` with base =
the replayed commit's first parent (root commits use an empty base) — no
second merge implementation, no object mutation. `cherry-pick` resolves like
`merge`: a clean replay advances the branch; a conflict writes P4-style
markers plus `.sc/PICK_HEAD` and the next `sc commit` completes it
single-parent, with `sc status` reporting the pick in progress. `rebase` is
atomic: it refuses up front if a merge commit sits in the replayed range, and
the first conflict aborts the whole rebase with refs and the working tree
untouched (unlike cherry-pick's per-commit markers). Both write the CAS
snapshot, materialize the working tree, and only then move the branch ref —
the ref update is the atomic commit point, matching `merge`'s crash
discipline. An append-only `.sc/oplog` records HEAD and every touched ref
before/after each ref-moving operation (including secret/protect ops and
`sc work` sessions); `sc undo` restores the last record's before-state and
logs its own inverse record, so a second `sc undo` redoes the first; `sc
oplog` lists records newest-first. Undoing the repo's initial commit is
refused (would unbear the branch) as a deliberate scope cut. `sc gc` treats
oplog-referenced snapshot ids as reachability roots and trims records past
the prune-expire window, always keeping the newest. Protected content fails
closed → lifted in P15 (ADR-0025): replay refuses any commit touching
PROTECTED paths, inheriting P4's merge guard verbatim. The oplog is
local-only, like a reflog — it never travels over `fetch`/`push`/`clone`.
Replay does not carry secret-registry changes: `sc rebase`/`sc cherry-pick`
warn (stderr) when they skip a commit's registry change rather than
replaying it (follow-on: registry replay → closed in P15). See ADR-0024.

**Phase 15 is built.** Protected content no longer fails closed on
merge/rebase/cherry-pick. Id-level cases (unchanged / one-side-changed /
clean-delete protected paths) resolve as ciphertext-id fast paths — sound
under convergent encryption, no identity required — carrying ciphertext +
unioned wrapped DEKs. Only content-divergent protected paths (both sides
edited the plaintext) need `--identity`: the plaintexts are decrypted,
diff3-merged, and re-encrypted through the same `encrypt_protected`/
`reuse_prior_wraps` helpers `commit` uses, so plaintext is never written to
the CAS (`Error::ProtectedMergeNeedsIdentity` when identity is missing,
`Error::NotAuthorized` when the supplied identity can't unwrap). Protection
rules merge by union (`union_prefixes`/`union_wraps`, both deterministically
sorted) — nothing silently unprotects, including the I2 rule: a carried
PLAIN file that matches a landing union rule is re-encrypted at completion,
so "protected" and "ciphertext" stay synonymous in every snapshot. Conflicted
protected merges/picks write plaintext markers only to the identity-holder's
working tree (never the CAS) and persist the decided tree
(`MERGE_DECIDED_ROOT`/`PICK_DECIDED_ROOT`, gc-rooted and gated on their
in-progress HEAD so crash residue can't hijack a later completion);
completion unions both sides' rules/wraps and carries absent protected files
from the decided tree rather than picking one parent. The secret registry
now replays through rebase/cherry-pick (`merge_secrets`, base = the replayed
commit's own parent; conflicts abort atomically), and replay's `Empty` means
tree **and** registry **and** protection-prefix deltas are all empty, so a
rules-only or secrets-only commit replays instead of being silently skipped.
`decrypt_with` distinguishes ciphertext corruption from a genuine
authorization failure. `MergeProtected`/`ReplayProtected` are retired.
`crypto::Zeroizing` is re-exported through the crate boundary so callers
outside `crates/crypto` can zero decrypted buffers without a second
dependency on RustCrypto/`zeroize` (the quarantine still holds — only the
type alias crosses). See ADR-0025.

Remaining follow-ons: network Git remotes, HTTP transport, streaming (>4 GiB)
frames, bulk re-wrap, multiple escrow keys, interactive workspace sessions,
auto-merge of clean workspace results, `sc amend`, stop-and-continue rebase
(`--continue`), cherry-pick `--abort`, merge-commit replay (mainline
selection), operation objects in the CAS, and oplog entries for
remote-tracking refs.
