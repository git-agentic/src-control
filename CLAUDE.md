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

```
crates/core   → content-addressed store, object model, budget + eviction
crates/vfs    → in-memory worktree engine (depends on core)
crates/gitio  → Git import via gix (depends on core; ONLY crate that links gix)
crates/crypto → envelope encryption (depends on core; ONLY crate linking RustCrypto)
crates/tlsio  → TLS for sc+https (depends on nothing; ONLY crate linking rustls/rcgen)
crates/repo   → persistent .sc/ repo: objects, refs, branches, working tree (depends on core/vfs/crypto/tlsio)
crates/cli    → `sc` binary (depends on repo + vfs + gitio + crypto + core)
apps/desktop/src-tauri → Tauri read-only adapter (depends on repo + core + crypto)
apps/desktop/src       → bundled TypeScript presentation (typed IPC only)
```

Strict dependency direction: top-level adapters `{cli, desktop} → repo →
{vfs, gitio, crypto, tlsio} → core`
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

```sh
cargo test                                   # whole workspace
cd apps/desktop && npm ci                    # desktop JS dependencies
cd apps/desktop && npm run tauri dev         # native desktop development app
cd apps/desktop && npm run typecheck && npm test
cd apps/desktop && npm run tauri build -- --bundles app  # validated macOS production bundle
cargo run --bin sc -- demo --agents 4        # parallel-agent demo
cargo run --bin sc -- demo --agents 6 --budget-mb 4 --spill   # exercise eviction
cargo run --bin sc -- import --repo <path>   # import a Git repo's HEAD
bash demo/run_demo.sh                         # independent zero-residue proof
cargo run --bin sc -- keygen                 # v2 identity: one seed derives BOTH an X25519
                                             # encryption key and an Ed25519 signing key (P22);
                                             # a pre-P22 v1 (scl-sk-) identity still parses and
                                             # still encrypts, but cannot sign
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
cargo run --bin sc -- branch <name> --private --to <recipient>... [--identity <key>]
                                             # create a PRIVATE branch (P34): commits/trees/
                                             # blobs sealed to the recipient set (creator +
                                             # escrow always wrapped in); opaque to non-
                                             # recipients until publish; flat name only
                                             # (grammar unchanged); KEEP identity files OUTSIDE
                                             # the working tree (a committed key is sealed in
                                             # and vanishes on the next switch)
cargo run --bin sc -- branch grant <name> --to <recipient> --identity <key>   # wrap the branch
                                             # KEK for another recipient — O(1), no object churn
cargo run --bin sc -- branch revoke <name> --recipient-id <id> --identity <key>   # revoke +
                                             # atomically rotate the KEK + rewrap for everyone
                                             # remaining (zero content plaintext, zero id churn;
                                             # a revoked recipient keeps what they already
                                             # fetched — rotation ≠ erasure)
cargo run --bin sc -- branch publish <name> --identity <key>   # replay the sealed history as
                                             # PUBLIC commits (messages/authors kept, new ids by
                                             # construction, published commits start unsigned);
                                             # scanner runs over decrypted content before any
                                             # public write; branch becomes ordinary + public
cargo run --bin sc -- branch list [--json] [--identity <key>]   # list branches; private ones
                                             # marked (private) / (private, no access)
cargo run --bin sc -- switch <name> [--identity <key>]   # switch branch + materialize working
                                             # tree; a private branch needs a recipient --identity
cargo run --bin sc -- status --identity <key>   # (and diff/log) need --identity on a private branch
cargo run --bin sc -- merge <public-branch> --identity <key>   # ON a private branch: merges the
                                             # public branch IN (keeps an embargo current); the
                                             # reverse (merge/cherry-pick/rebase FROM a private
                                             # branch) is refused — publish first
cargo run --bin sc -- merge <ref> [--identity <key>]   # three-way merge (ff when possible; exits
                                             # 1 on conflicts; --identity only needed when a
                                             # protected path diverged in content on both sides)
cargo run --bin sc -- conflicts [<path>] [--identity <key>] [--json]
                                             # no path: lists conflicted paths + kind (text/
                                             # binary/protected); with path: base/ours/theirs,
                                             # decrypted under --identity for protected paths (P23)
cargo run --bin sc -- resolve --ours|--theirs <path>... [--identity <key>]
                                             # writes the chosen side's clean content, drops
                                             # sidecars, clears the path from the active
                                             # merge/pick/rebase conflict record (P23)
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
bash demo/run_protect_demo.sh                # encrypted-paths proof (P7): protected path commits
                                             # as ciphertext, unreadable in a keyless clone,
                                             # decrypts only for the recipient
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
                                              # exits 1 when entries were skipped); also
                                              # eagerly re-seals any still-CONVERGENT (pre-P33)
                                              # protected blob RANDOMIZED (P33) — so a rewrap
                                              # that upgrades content is no longer tree-identical,
                                              # while a second rewrap over an all-randomized tip
                                              # converges back to policy-only
cargo run --bin sc -- escrow add <pubkey-or-name>    # append a break-glass key (list)
cargo run --bin sc -- escrow remove <id-or-name>
cargo run --bin sc -- escrow show                    # lists all escrow keys
bash demo/run_rewrap_demo.sh                          # bulk rewrap + escrow-list proof
bash demo/run_randomized_demo.sh                      # randomized protected-encryption proof
                                              # (P33): same plaintext → different ciphertext ids
                                              # (oracle closed), quiet history for unchanged
                                              # content, cost-4a identical-edit conflict, and
                                              # sc rewrap policy-only on an all-randomized tip —
                                              # run twice, zero residue (the convergent→randomized
                                              # rewrap UPGRADE and pre-P33 dual-read are unit-
                                              # test-pinned, since the current binary can no
                                              # longer write a convergent blob)
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
cargo run --bin sc -- commit -m "msg" --sign [--identity <key>]   # sign the new tip (P22;
                                              # requires a v2 identity — see `sc keygen`)
cargo run --bin sc -- amend [-m <msg>] --sign [--identity <key>]  # sign the amended tip (P22)
cargo run --bin sc -- sign <ref> [--identity <key>]   # retroactively sign any ref's tip
                                              # snapshot (P22; also the MVP path for signing a
                                              # merge/pick/rebase result — re-sign after)
cargo run --bin sc -- verify [<ref>] [--require]   # walk history (all parents, not just
                                              # mainline), report each commit's signature
                                              # status (trusted ✓ / untrusted ? / INVALID ✗ /
                                              # unsigned); --require exits 1 unless every
                                              # commit is trusted (P22)
cargo run --bin sc -- transcript attach <ref> <file> [--agent <name>] [--sign] [--identity <key>]
                                              # seal an agent-session transcript (P30) and attach
                                              # it to <ref>'s tip; body sealed to the full
                                              # [recipients] set + escrow — plaintext never enters
                                              # the CAS (keyless clone gets ciphertext only);
                                              # --sign attests the transcript id (opt-in)
cargo run --bin sc -- transcript show <ref> [--identity <key>]   # decrypt + print a tip's
                                              # transcripts (needs --identity)
cargo run --bin sc -- transcript list [<ref>] [--json]   # list transcripts (never decrypts)
cargo run --bin sc -- transcript sign <ref> [--identity <key>]   # retroactively sign a tip's
                                              # transcript(s) (P30)
cargo run --bin sc -- ws harvest --transcript <path> [--sign] [--identity <key>]   # attach the
                                              # file to each harvested workspace's landed snapshot
                                              # (P30; landing status prints before the attach)
bash demo/run_transcript_demo.sh              # session-transcript proof (P30): attach --sign,
                                              # clone rides the pack, keyless clone = ciphertext,
                                              # identity decrypts byte-exact, sc log marker, gc
                                              # prunes a transcript with its dead snapshot
bash demo/run_provenance_demo.sh              # signed-history + rewrite-attack proof (P22):
                                              # alice signs, clone verifies clean, `sc amend`
                                              # in the clone is caught by `sc verify --require`
                                              # while the original stays clean, bob's
                                              # retroactive `sc sign` shows ? until trusted
bash demo/run_merge_ergonomics_demo.sh        # sc conflicts/sc resolve proof (P23): a text
                                              # conflict and a protected (identity-decrypted)
                                              # conflict both resolved end-to-end with no
                                              # hand-edited markers
cargo run --bin sc -- sparse set <prefix…> [--identity <key>]   # narrow the working tree to
                                              # these path prefixes; re-lays disk now (P24)
cargo run --bin sc -- sparse show [--json]    # list the active sparse prefixes ("disabled" if
                                              # the spec is empty/absent) (P24)
cargo run --bin sc -- sparse disable [--identity <key>]   # clear the spec and rematerialize
                                              # every subtree in full (P24)
bash demo/run_sparse_demo.sh                  # sparse checkout proof (P24): narrow to one of
                                              # three subtrees, edit + commit under sparse, then
                                              # sc sparse disable AND an independent full clone
                                              # both restore the other two byte-identical
bash demo/run_streaming_demo.sh               # streaming pack transfer proof (P25): a forced
                                              # SC_PACK_CHUNK=4096 crosses a ~1 MiB signed blob
                                              # in 250+ chunk frames, byte-for-byte clone, zero
                                              # .sc/tmp residue on either end
cargo run --bin sc -- serve --http <addr> <path> [--read-only] [--allow-public]
                             [--max-connections <n>] [--timeout <secs>] [--max-pack-size <bytes>]
                                              # sc-native wire protocol over TCP (P26); e.g.
                                              # `sc serve --http 127.0.0.1:8730 .`; exactly one
                                              # of --stdio/--http is required; a non-loopback
                                              # <addr> is refused unless --read-only,
                                              # --allow-public, or — with --tls — a configured
                                              # serve token justifies it (P29, narrowed by P32)
                                              # --max-connections <n>: concurrent-connection cap,
                                              # --http only, default 32, 0=unlimited; at the limit
                                              # a new connection gets busy-status-and-close, no
                                              # queuing (P31)
                                              # --timeout <secs>: session idle/progress timeout,
                                              # --http only, default 300, 0=disabled; read+write,
                                              # persists the whole session, connection-fatal on
                                              # trip; opening keeps its own 30s (P31)
                                              # --max-pack-size <bytes>: incoming-pack aggregate
                                              # cap, both --http and --stdio, default 16 GiB,
                                              # 0=unlimited, floor 256 MiB (MAX_OBJECT_SIZE);
                                              # counted mid-stream abort -> EC_TOO_LARGE (P31)
cargo run --bin sc -- serve token add --label <name> --scope ro|rw   # mint an
                                              # sct-<hex> bearer token in .sc/serve-tokens.toml;
                                              # raw value prints once on stdout (P29)
cargo run --bin sc -- serve token remove <label>   # drop a token by label (P29)
cargo run --bin sc -- serve token list [--json]    # list token labels + scopes, never the
                                              # raw value (P29)
                                              # client: SC_HTTP_TOKEN=<raw> sc clone/fetch/push
                                              # sc+http://... presents the bearer on every
                                              # connection once any token is configured (P29)
cargo run --bin sc -- clone sc+http://host[:port]/repo <dst>   # clone over sc+http:// (P26;
                                              # port defaults to 8730); sc remote add/fetch/push
                                              # accept the same sc+http:// URL form
bash demo/run_http_remote_demo.sh             # sc-native HTTP transport proof (P26): real
                                              # loopback TCP (no shim, unlike ssh://), clone +
                                              # push + fetch over sc+http://, a signed ~1 MiB
                                              # blob byte-for-byte, zero .sc/tmp residue
cargo run --bin sc -- clone --filter <prefix…> <src> <dst>   # partial clone (P27): fetch
                                              # ONLY objects reachable under these path
                                              # prefixes; writes .sc/promisor + .sc/sparse to
                                              # the same prefixes; not supported over a
                                              # git-bridge remote
cargo run --bin sc -- backfill <prefix…>      # widen a partial clone: fetch objects under
                                              # these prefixes from the promisor origin and
                                              # widen .sc/promisor; errors if this repo isn't
                                              # a partial clone (P27)
cargo run --bin sc -- backfill --all          # fetch EVERY remaining object (no prefix
                                              # restriction), verify the closure is complete,
                                              # then remove .sc/promisor — this repo becomes a
                                              # genuine full clone and merge/pick/rebase/ws
                                              # fork/harvest/sc work/export/sparse disable all
                                              # work again (P27 final review I2)
bash demo/run_partial_clone_demo.sh           # partial clone proof (P27): sc clone --filter
                                              # src/ fetches fewer objects than a full clone
                                              # (object-store count + sc verify's gap report);
                                              # docs/lib/ never fetched or materialized; a
                                              # src/ edit committed+pushed from the partial
                                              # clone lands cleanly (full re-clone sees the
                                              # edit AND byte-identical docs/lib); sc backfill
                                              # docs/ shrinks the gap count; sc gc succeeds and
                                              # preserves everything; run twice
bash demo/run_http_auth_demo.sh               # sc+http access-control proof (P29): a no-token
                                              # clone is rejected with an authentication error,
                                              # an ro-token clone reads but its push is rejected
                                              # read-only, an rw-token push lands and a later
                                              # ro-token clone sees it, an unjustified 0.0.0.0
                                              # bind is refused while --allow-public opens it
                                              # deliberately, zero .sc/tmp residue anywhere
cargo run --bin sc -- serve --http <addr> <path> --tls [--tls-cert <pem> --tls-key <pem>]
                                              # TLS listener (P32): sc+https://; auto-mints a
                                              # self-signed identity into .sc/serve-tls/ (key
                                              # 0600, key-is-identity) unless PEM given; banner
                                              # prints the SPKI fingerprint; NB gate change:
                                              # tokens justify a non-loopback bind ONLY with
                                              # --tls now — plaintext public needs
                                              # --allow-public (or --read-only)
cargo run --bin sc -- serve fingerprint [<path>]   # print (minting if absent) the serve-TLS
                                              # SPKI fingerprint (sha256:<hex>)
cargo run --bin sc -- clone sc+https://host[:port]/repo <dst>   # TLS clone (P32); accept-new
                                              # TOFU: first connect pins into
                                              # ~/.config/sc/known_hosts (SC_HTTPS_KNOWN_HOSTS
                                              # overrides), mismatch always hard-fails;
                                              # SC_HTTPS_FINGERPRINT=<sha256:hex> pre-pins (CI),
                                              # SC_HTTPS_STRICT=1 refuses unknown hosts;
                                              # remote add/fetch/push accept the same URL form
bash demo/run_tls_demo.sh                     # sc+https proof (P32): TLS round trip w/ signed
                                              # chunked blob, TOFU pin/mismatch/strict/pre-pin,
                                              # tightened plaintext gate — run twice
bash demo/run_private_branch_demo.sh          # private branch proof (P34): alice stages an
                                              # embargoed fix on a private branch, keeps it
                                              # current by merging main IN; a keyless clone gets
                                              # ciphertext + a name marker only (content/paths/
                                              # message opaque, every read surface refuses);
                                              # grant admits bob, revoke rotates the KEK so a
                                              # post-revoke clone can't open it while bob's pre-
                                              # revoke clone still can (rotation ≠ erasure);
                                              # private→public integration + git export refuse;
                                              # publish flips it public atomically — run twice,
                                              # zero residue
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
