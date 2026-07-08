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
cargo run --bin sc -- revoke <prefix> --recipient-id <id>                # path-protection revoke;
                                             # tombstone-durable across merges of pre-revoke
                                             # branches (P16)
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
                                                                # (replace-with-one sugar, P17)
bash demo/run_lifecycle_demo.sh                                # rotation + escrow proof
cargo run --bin sc -- rewrap [--identity <key>] [--dry-run]   # one-commit bulk reseal of all
                                              # secrets + protected wrap lists to current
                                              # recipient/escrow sets (skip-and-report;
                                              # exits 1 when entries were skipped)
cargo run --bin sc -- escrow add <pubkey-or-name>    # append a break-glass key (list)
cargo run --bin sc -- escrow remove <id-or-name>
cargo run --bin sc -- escrow show                    # lists all escrow keys
bash demo/run_rewrap_demo.sh                          # bulk rewrap + escrow-list proof
cargo run --bin sc -- work --agents 3 -- <cmd>   # fork agent workspaces, run <cmd> in each,
                                                 # harvest changed ones to work-<i> branches
                                                 # (--with-secrets --identity <key> injects
                                                 # decrypted secrets into each agent env)
bash demo/run_work_demo.sh                       # parallel-agents round-trip proof
cargo run --bin sc -- ws fork --agents N [--identity <key>]  # durable multi-invocation
                                              # session: materializes N checkouts under
                                              # .sc/ws/<i>/ and persists a manifest (P20)
cargo run --bin sc -- ws list                 # open session's workspaces, changed/unchanged
cargo run --bin sc -- ws run <i> [--with-secrets --identity <key>] -- <cmd>   # run <cmd> in
                                              # workspace i (SC_WORKSPACE/SC_WORKSPACE_DIR set)
cargo run --bin sc -- ws harvest [--into <branch>] [--identity <key>]   # probe + auto-merge
                                              # every live workspace onto the landing branch
                                              # (default the session's base branch, which must
                                              # be checked out); clean lands cumulatively,
                                              # conflicts fall back to work-<i>
cargo run --bin sc -- ws abandon [<i>]        # drop one workspace or the whole session
bash demo/run_ws_demo.sh                      # multi-invocation session + auto-merge proof (P20)
cargo run --bin sc -- cherry-pick <ref> [--identity <key>]   # replay one commit onto the
                                              # current branch (--identity as above)
cargo run --bin sc -- cherry-pick <ref> --mainline <N>       # replay a merge commit relative
                                              # to its Nth (1-indexed) parent; required for
                                              # merge commits, refused on non-merges (P19)
cargo run --bin sc -- cherry-pick --abort     # abandon a stopped pick; restores the
                                              # untouched tip (no oplog record — no ref
                                              # ever moved) (P19)
cargo run --bin sc -- rebase <target> [--identity <key>]     # replay current branch onto
                                              # <target>; a conflict STOPS (not aborts) with
                                              # persisted state — resolve then --continue
                                              # (default since P19; --identity as above)
cargo run --bin sc -- rebase --continue [--identity <key>]   # resume a stopped rebase;
                                              # any number of stops still collapses into ONE
                                              # oplog record / ONE undo (P19)
cargo run --bin sc -- rebase --abort          # abandon a stopped rebase; restores the
                                              # pre-rebase working tree (P19)
cargo run --bin sc -- amend [-m <msg>]        # rebuild the tip from the working tree, tip's
                                              # own parents kept, message kept unless -m (P19)
cargo run --bin sc -- undo                    # revert the last operation (again = redo)
cargo run --bin sc -- oplog                   # list recent operations
bash demo/run_history_demo.sh                 # cherry-pick/rebase/undo round-trip proof
bash demo/run_protected_merge_demo.sh         # protected merge & replay proof (P15)
bash demo/run_revoke_demo.sh                  # revocation-tombstone durability proof (P16)
cargo run --bin sc -- clone <git-url> <dst> [--git]   # auto-detects hosted-git URL forms
                                              # (https://, http://, scp-style git@host:path,
                                              # file://) and routes through the git mirror
                                              # bridge (P18); bare ssh:// stays sc-native (P12)
                                              # unless --git forces the mirror path; network
                                              # forms require git on PATH (SC_GIT to override
                                              # the binary)
cargo run --bin sc -- remote add <name> <url> --git   # --git also accepts network URL forms
                                              # (https://, http://, scp-style, ssh://) as of
                                              # P18, alongside P10's local .git paths; --git
                                              # stays required in every case; network forms
                                              # require git on PATH (SC_GIT to override)
bash demo/run_network_git_demo.sh             # hosted-git round trip over file:// (P18; prints
                                              # the real-GitHub recipe: sc remote add origin
                                              # git@github.com:… --git)
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
`.git` paths on disk only; network Git is deferred — lifted in P18 (network Git
via system-git mirror bridge). One accepted MVP
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
an actual cryptographic cutover. `sc escrow {add,remove,show}` / `sc escrow set` (single break-glass key →
managed list in P17; `set` kept as replace-with-one sugar) in
`.sc/recipients.toml [escrow]`, auto-appended (deduped) whenever `secret add`,
`secret rotate`, or `protect` seals/wraps — forward-only (existing secrets/paths
gain escrow only when next rotated/re-wrapped) and policy, not enforcement
(nothing stops a caller from bypassing the CLI and omitting it). **Rotation ≠ erasure:**
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
plain `sc merge` **→ multi-invocation sessions in P20** (durable
checkout-backed sessions that survive across process boundaries, with
auto-merge replacing the manual `sc merge` step; see below). HEAD, the
current branch, and the user's working tree are never touched; a failed
agent's partial work is still harvested; teardown leaves zero residue
outside `.sc/`. Branch names are flat because the ref grammar reserves
`name/branch` for remote-tracking refs. See ADR-0023.

**Phase 14 is built.** History editing: `sc cherry-pick <ref>` and `sc rebase
<target>` are both replay, composed from P4's `three_way_files` with base =
the replayed commit's first parent (root commits use an empty base) — no
second merge implementation, no object mutation. `cherry-pick` resolves like
`merge`: a clean replay advances the branch; a conflict writes P4-style
markers plus `.sc/PICK_HEAD` and the next `sc commit` completes it
single-parent, with `sc status` reporting the pick in progress. `rebase` is
atomic: it refuses up front if a merge commit sits in the replayed range, and
the first conflict aborts the whole rebase with refs and the working tree
untouched (unlike cherry-pick's per-commit markers) — **→ resumable in P19**
(stop-and-continue replaces abort-on-conflict as the default; see below).
Both write the CAS
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
**Boundary (closed in P16):** because protection rules merge by union, a
prefix-rule revoke (`sc revoke`) was not durable against merging any branch
created before the revoke — the union re-added the recipient and future
commits under that prefix sealed fresh DEKs to them. P16's per-recipient
revocation tombstones (below) close this: revoke now survives merging any
pre-revoke branch. See ADR-0025.
`decrypt_with` distinguishes ciphertext corruption from a genuine
authorization failure. `MergeProtected`/`ReplayProtected` are retired.
`crypto::Zeroizing` is re-exported through the crate boundary so callers
outside `crates/crypto` can zero decrypted buffers without a second
dependency on RustCrypto/`zeroize` (the quarantine still holds — only the
type alias crosses). See ADR-0025.

**Phase 16 is built.** `sc revoke` is now durable across merges. Each
protection rule's recipient standing is a per-recipient last-writer-wins
register — `RecipientEntry { key, epoch, state: Granted | Revoked }` — in
place of the bare key list; grant/revoke mint a fresh `epoch = max(current)
+ 1`, and `merge_prefixes` keeps the higher-epoch entry per recipient,
resolving an epoch tie with disagreeing states as **Revoked** (fail-closed).
Commit-time sealing reads the effective set through `granted_keys()` —
Granted entries only, so a tombstoned recipient never seals a fresh DEK
again even when a pre-revoke branch is merged in later. `sc grant`'s
authorization check and `--identity` decryption (`decrypt_with`) are
unchanged: they work by wrap presence in `protection.wrapped`, and
`union_wraps` deliberately preserves old wraps as historical facts, so a
revoked recipient can still decrypt ciphertext sealed before the revoke
(they already held the key; cryptographic cutover is rotation, not
revoke). Corollary: merging a pre-revoke branch re-attaches the revoked
recipient's old wraps to the live tip, and since `grant` authorizes by
wrap presence, a revoked-but-wrap-holding recipient can still grant others
access to that pre-revoke ciphertext — standing and fresh seals stay
tombstone-gated regardless. **P17's `sc rewrap` is the practical answer to
this corollary:** it replaces the live tip's wrap list with exactly the
rule's current `granted_keys() + escrow`, stripping the re-attached wraps
from the tip in one commit (history keeps them, per the ADR-0019
boundary). Crossed revokes can empty a rule's granted set
entirely; `encrypt_protected` is now fallible and refuses the seal loudly
(pointing at `sc grant`) rather than minting ciphertext nobody can read.
This is a rules-format break: the snapshot tag bumped `2 → 4`
(`TAG_SNAPSHOT_LEGACY = 2`), so a pre-P16 store fails to decode with an
explicit "pre-P16 snapshot encoding" error instead of silently misparsing
the new layout. A second `sc protect` on an already-protected prefix
changed from replacing the rule wholesale to extending/re-granting at the
next epoch, so tombstones survive re-protect. `sc protect --list` gained
`--json` and per-recipient `granted@eN` / `REVOKED@eN` rendering. This
closes the ADR-0025 boundary note: merging any branch created before a
revoke no longer resurrects the revoked recipient. See ADR-0026.

**Phase 17 is built.** `sc rewrap [--identity <key>] [--dry-run]` is a
one-command, one-commit, one-oplog-record bulk cutover of every secret and
protected blob at the tip to the current recipient/escrow sets — undoable
like any other ref-moving operation. Secrets are recovered with the
identity and re-sealed under a fresh DEK to their current recipients plus
the full escrow list (P11's rotate machinery, batched into a single
registry commit); every PROTECTED blob has its DEK unwrapped by wrap
presence and its wrap list **replaced** with exactly the governing rule's
`granted_keys() + escrow`, so a tombstoned recipient's wraps re-attached by
a pre-revoke merge do not survive the sweep. Convergent DEKs keep
ciphertext ids unchanged, so the commit is policy-only (root tree
byte-identical). **Skip-and-report:** entries the identity cannot open are
skipped and named (not silently dropped); the command commits whatever it
could and exits non-zero when anything was skipped, printing a hint to
re-run with an identity that can open the rest. **Honesty caveat (same
ADR-0019 boundary):** rewrap cuts the live tip only — old snapshots in
history keep their old wraps and old secret objects via content
addressing, so real cutover of an external credential still means
rotating the credential itself. Escrow is now a managed list rather than a
single key: `sc escrow add/remove/show` join `set` (kept as
replace-with-one sugar); `.sc/recipients.toml [escrow]` grows from
`key = "…"` to `keys = […]` (old singular form still read on load, every
write normalizes to `keys`, and an empty list drops the section). This is
the practical answer to the ADR-0026 R1 corollary above: change the
escrow/recipient set, run one `sc rewrap`, and the re-attached wraps are
gone from the live tip. See ADR-0027.

**Phase 18 is built.** Hosted Git (GitHub over https/ssh) is now reachable
via a system-git mirror bridge, because upstream `gix` (pinned 0.85) can
fetch/clone but not push — a pure in-process network path is impossible
today. Each git-backed network remote keeps a lazily-created bare mirror
at `.sc/git-remotes/<name>/mirror.git`, beside (not replacing) P10's
`marks` file in the same directory; deleting `mirror.git` is always safe
(next op reconstructs it), deleting `marks` is not (it carries `git_oid
↔ sc_id` identity). The spawned system `git` binary (`crates/gitio/src/
bridge.rs`) is transport-only: `sc fetch` runs `git fetch --prune` into
the mirror, then P10's unchanged in-process import; `sc push` runs P10's
unchanged export into the mirror, then `git push`, reusing the P9/P10
confidentiality gate verbatim. `sc clone <git-url> <dst>` composes init +
`remote add --git` + fetch + adopt-default-branch. Auth is fully
delegated to the spawned `git` (ssh-agent, credential helpers, tokens);
its stderr passes through unmodified and `sc` has no credential surface.
Clone routing auto-detects unambiguous git URL forms — `https://`,
`http://`, scp-style `git@host:path`, `file://` — none of which can ever
mean an sc-native remote; bare `ssh://` stays sc-native (P12/ADR-0022)
unless `--git` forces the mirror path. `sc remote add <name> <url> --git`
now also accepts these network forms, but `--git` stays required there in
every case (no clone-time ambiguity to resolve). `file://` deliberately
routes through the bridge too, so tests and `demo/run_network_git_demo.sh`
exercise git's genuine transport/pack code hermetically. `SC_GIT`
overrides the spawned binary (the P12 `SC_SSH` pattern); `git` becomes a
runtime requirement for network remotes only — local-path git remotes and
everything else keep working without it. A review Critical: `export_branch`
advances the *mirror's* ref, not the network's, so the fast-forward gate
must not treat "mirror matches local tip" as "nothing to push" for network
remotes — `sc push` now always runs the network leg (`mirror_push`) before
any success output, even on that branch, so a previously-failed push is
retried instead of silently reported up to date (regression test:
`network_push_failure_is_retryable`). See ADR-0028.

**Phase 19 is built.** History-editing ergonomics, riding the existing
P14/P15 replay core with no second merge implementation. `sc amend [-m
<msg>]` rebuilds the tip commit from the current working tree with the
tip's own parents kept (merge and root commits amend naturally), message
kept unless `-m` overrides, through the full commit pipeline (scanner,
`.scignore`, protected re-encryption, registry carried) — it reuses the
shared `snapshot_files` pipeline via a `parents_override` parameter, so
there is one commit-assembly path, not a parallel one. **Resumable
rebase is now the default** (revising P14's atomic-abort): a conflict
stops with P4 markers and persisted `.sc/REBASE_STATE` rather than
aborting the whole rebase; `sc rebase --continue [--identity]` completes
the conflicted commit (via `assemble_completion_snapshot`, extracted out
of `commit`'s pick-completion arm so pick and rebase completion share one
implementation) and resumes the fold (`rebase_fold_and_finish`, shared by
`rebase`'s first pass and every resumed continuation) — any number of
stops still collapses into ONE oplog record and ONE `sc undo` for the
whole operation, because the branch ref only moves at final completion.
`sc cherry-pick --abort` clears pick state and restores the untouched tip
(no oplog record — no ref ever moved, so abort is its own inverse). `sc
cherry-pick <ref> --mainline <N>` replays a merge commit relative to its
Nth (1-indexed) parent; merge picks without the flag stay refused, now
with a hint; `--mainline` on a non-merge errors. Rebase over a
merge-containing range stays refused, with a hint to linearize or drop it
first (a rebase replays a whole range, so there's no single "relative to
which parent" a flag could resolve). A review Critical: `rebase
--continue` originally cleared `REBASE_STATE` before running the resumed
fold, so a typed error (missing `--identity`, authorization failure, a
secret-registry conflict) on a later commit in the range destroyed
resumability — no retry, no abort. State is now cleared only by the
fold's own completion tail or overwritten by the next stop; a `resolved`
flag on `RebaseState` makes a retried `--continue` idempotent (it skips
re-completing the already-landed commit). A second Important: mainline
picks originally based the secret-registry three-way on the commit's
first parent while file replay based it on the chosen parent N — a silent
wrong-registry bug, closed by threading the same resolved parent
(`base_override`) through both. `rebase_abort`/`cherry_pick_abort` both
needed a deletion baseline (the stop's `REBASE_DECIDED_ROOT`/
`PICK_DECIDED_ROOT` as `old_root`, mirroring `merge_abort`'s pattern) —
review caught that a full clean materialize (`old_root: None`) left
stop-materialized theirs-side-only files as untracked residue. Proven by
the extended `demo/run_history_demo.sh`: an interrupted-and-resumed
rebase asserting exactly one new oplog record, an aborted cherry-pick
verified byte-identical by checksum, and an `sc amend` message fix with
history length unchanged. See ADR-0029.

**Phase 20 is built.** Agent sessions outlive a single process. `sc ws
fork --agents N [--identity <key>]` materializes N checkouts under
`.sc/ws/<i>/` (P7-aware, as P13) and atomically writes
`.sc/ws/session.toml` (base snapshot, base branch, workspace dirs +
status, author — never key material); the checkout dirs ARE the durable
state, so `sc ws list`/`run` (P13 env/secret-injection parity,
`SC_WORKSPACE`/`SC_WORKSPACE_DIR`) and `sc ws harvest`/`abandon` work
across any number of later invocations, even a different day. `sc ws
harvest [--into <branch>] [--identity <key>]` runs each live workspace
through P13's `harvest_workspace` pipeline (`.scignore`, P5 scanner
gate, protected re-encryption), then auto-merges the resulting candidate
onto the landing branch — default the session's base branch, `--into`
overrides — via a read-only conflict probe (`would_merge_cleanly`,
composing `three_way` + `merge_secrets` with input assembly
byte-identical to `merge_with_identity`) that guarantees no conflict
markers land unattended: clean merges (including ff) land immediately,
one oplog record per landing, cumulatively (a later workspace's merge
sees every earlier landing already folded in); anything conflicted —
including protected divergences lacking `--identity` — falls back to a
collision-suffixed `work-<i>` branch exactly as P13 does, landing branch
untouched. The landing branch must be the currently-checked-out branch
(default or `--into`): the merge machinery `ws_harvest` reuses whole is
head-centric, and harvest refuses with a `sc switch` hint otherwise,
rather than re-deriving a headless merge variant. A scanner-Rejected
workspace stays LIVE, not terminal: no candidate branch was ever
created, so the offending file can be fixed in place in the same
checkout dir and re-harvested — P13 treated rejection as terminal for
its one-shot session, but a durable session can do better. Harvest is a
ref-mover and joins the P19 merge/pick/rebase-in-progress guard family;
a dirty-tree preflight runs before any candidate branch is minted (there
is no CLI command to delete a stray branch, so the class is eliminated
rather than guarded against after the fact). `resolve_and_teardown`
writes the manifest before removing the workspace dir, so a crash
between the two never leaves a `live = true` entry pointing at a
directory that no longer exists. A crash-recovery re-harvest that
re-mints an already-landed candidate (same parent/tree/author/message at
the same wall-clock second) resolves `Err(UpToDate)` as an idempotent
no-op `Landed`, not an error. A probe/merge disagreement (a bug, not a
normal conflict) bails loudly stating conflict markers ARE on disk with
a merge now in progress, resolvable via markers + `sc commit`. `sc work`
(P13) is unchanged; teardown leaves `.sc/ws/` gone once every workspace
is harvested or abandoned. Proven by `demo/run_ws_demo.sh`: fork in one
invocation, edit workspaces in another, harvest in a third — two clean
auto-merges land cumulatively, one conflict falls back to `work-<i>`,
`sc undo` reverts the last landing, and session end leaves zero residue.
See ADR-0030.

Remaining follow-ons: HTTP transport, streaming (>4 GiB) frames,
operation objects in the CAS, and oplog entries for remote-tracking refs.
