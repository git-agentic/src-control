---
name: sc-cli-reference
description: Full annotated reference for the sc CLI in src-control — every subcommand with flag semantics and gotchas, plus each demo/*.sh proof script. Use before running, scripting, or explaining any `sc` command, demo, or proof script.
---

# sc CLI & demo reference

Annotated command reference migrated from the root `CLAUDE.md` (2026-07-15).
Semantics noted here are current facts; the authoritative rationale lives in
the ADRs under `docs/adr/` and the design in `ARCHITECTURE.md`.


```sh
cd apps/desktop && npm run tauri dev         # native desktop development app
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

