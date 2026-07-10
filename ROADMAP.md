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
- **Phase 25 — Streaming pack transfer (bounded-RAM, >4 GiB).** An
  incremental `PackWriter` (`crates/core/src/pack.rs`) appends objects one
  at a time to any `Write`, accumulating only the (small) index in RAM, and
  is byte-identical to `build_pack` for the same object sequence
  (`pack_writer_matches_build_pack_byte_for_byte`); a streaming
  `parse_pack_reader` verifies each record's BLAKE3 hash off a `Read`
  without holding the whole pack body, terminating cleanly at a
  record-boundary EOF since the pack format carries no object count. The
  wire (`crates/repo/src/wire.rs`) frames a pack as `ST_PACK_CHUNK`/
  `ST_PACK_END` opcodes under the unchanged `u32` frame header
  (`write_pack_stream`/`read_pack_stream`, `CHUNK_SIZE` = 1 MiB, overridable
  via `SC_PACK_CHUNK` for tuning/testing); `PROTOCOL_VERSION` bumped `1 → 2`
  with v1 dropped outright (one pack encoding, no legacy fallback — a
  version mismatch is rejected cleanly at the handshake). The sender
  (`LocalTransport::build_pack_tempfile`) streams objects one at a time into
  a temp pack file instead of collecting a `Vec<(ObjectId, Vec<u8>)>`; the
  receiver (`ingest_pack_file`) does a two-pass atomic-after-verify ingest —
  pass 1 verifies every record's hash writing nothing, pass 2 writes each
  verified object — so a corrupt or truncated pack never partially lands; a
  `TempPackGuard` RAII type removes the temp file on success or any error.
  No new user command — streaming is transparent to every existing
  `push`/`fetch`/`clone` invocation. Proven by `demo/run_streaming_demo.sh`
  (a ~1 MiB signed blob crosses an ssh:// clone with `SC_PACK_CHUNK=4096`
  forcing 250+ chunk frames; object set, working tree, and `sc log` are
  byte-for-byte identical to the origin, and `sc verify --require` is clean
  in the clone, proving the signature rode the chunked stream — run twice
  into fresh destinations, zero `.sc/tmp` residue on either end both
  times). **The client is bounded too (closed in the P25 final-review
  fix):** `crates/repo/src/sync.rs::transfer_objects` (the fetch/clone
  ingestion path) now spills `get_pack`'s output into a guarded temp file
  and ingests it via the same `ingest_pack_file` two-pass bounded machinery
  the server and wire use, peak RAM one object; `Repo::push` now collects
  only ids, then streams the outgoing pack to a guarded temp file one
  object at a time via a shared `write_ids_to_temp_pack` helper (also used
  by `LocalTransport::build_pack_tempfile`) before handing an opened `File`
  to `transport.put_pack`. Both temp files are removed on success and every
  error (`TempPackGuard`), pinned by
  `fetch_client_ingests_via_tempfile_zero_residue` and
  `push_client_builds_via_tempfile_zero_residue`. (ADR-0035.)
- **Phase 26 — sc-native HTTP transport.** A second network transport on
  the same seam P12 opened for SSH: `sc+http://host[:port]/repo` (port
  default 8730, `ScHttpUrl::parse`), a minimal hand-rolled HTTP/1.1
  opening (`write_client_opening`/`read_client_opening`/`write_status`/
  `read_status`, all bounded by `MAX_OPENING_BYTES` = 8 KiB against an
  unterminated/hostile opening), and `sc serve --http <addr> <path>` — a
  `TcpListener`, thread-per-connection, each connection handled end to end
  by `handle_http_connection` and isolated from the accept loop. The
  client (`HttpTransport::connect`) reads and maps the status line — `200`
  proceeds, `404` → `Error::NotARepo`, anything else → a clear protocol
  error — *before* the `WireClient` handshake, reusing the same
  `BufReader` for both so no over-read byte is lost; after the opening,
  the P25 chunk stream and P22 signatures ride the raw `TcpStream` with no
  HTTP framing on top. Zero new dependencies (`std::net` only — confirmed
  by an empty `git diff main -- '*Cargo.toml'`). Proven by
  `demo/run_http_remote_demo.sh`: a real loopback `sc serve --http`
  process (no shim, unlike ssh:// — this is genuine TCP), a ~1 MiB signed
  blob crosses `sc+http://` clone with `SC_PACK_CHUNK=4096` forcing many
  chunk frames, object set/working tree/`sc log` byte-for-byte identical
  to the origin, `sc verify --require` clean in the clone, a push from a
  second clone lands and a third clone's fetch sees it, and zero
  `.sc/tmp` residue on either end — run twice. Same standing boundaries as
  the ssh transport plus one new one: **plaintext only, no TLS**
  (`sc+https://` deferred), **no authentication** (front with a reverse
  proxy for production), and **not HTTP-proxy/CDN safe** (a strict proxy
  won't tunnel the post-opening raw protocol). (ADR-0036.)
- **Phase 27 — Partial clone.** The P25–P27 scale-&-reach horizon's
  capstone: `sc clone --filter <prefix…> <src> <dst>` fetches ONLY
  objects reachable under the given prefixes — `.sc/promisor`
  (`crates/repo/src/promisor.rs`) records the fetch-filter + promisor
  origin, and `Promisor::should_descend` is the ancestor-aware predicate a
  path-aware filtered reachability walk
  (`reachable_objects_filtered` → `Reachable { included, gaps }`,
  `crates/repo/src/reachable.rs`) needs to descend through an out-of-filter
  ancestor directory to reach deeper in-filter content, while pruning
  everything genuinely out of filter (recorded in `gaps` by id, never
  fetched — the reason a partial-clone source missing an out-of-filter
  object never errors). One walk serves both `get_pack`'s want-side filter
  (`PROTOCOL_VERSION` 2→3) and the client's own gap-tolerant `gc`/`sc
  verify` (`partial: N object(s) outside filter`, exit 0). Building a new
  commit on a partial clone needed real new machinery, not free
  composition: `worktree::graft_out_of_sparse` splices the tip's
  out-of-filter subtrees back into a freshly built root by id (never
  reading their content), closing two review-caught Criticals along the
  way — protected-blob wraps carried forward so decryption access isn't
  silently lost, and content under a never-fetched path refused outright
  (`Error::GappedPathContent`) rather than silently dropped. `sc backfill
  <prefix…>` widens the filter from the promisor origin on demand, offline
  everywhere else (explicit backfill, not transparent lazy-fetch — a
  deliberate MVP choice to keep network I/O out of every read path).
  **Coarse but honest limitation:** merge, cherry-pick/rebase replay, `sc
  ws harvest`, and `sc work` are refused entirely on a partial clone
  (`Error::PartialCloneUnsupported`) — backfill to a full clone first, not
  a per-case gap-tolerant reimplementation. `sc export` refuses too (Git
  needs full trees). Proven by `demo/run_partial_clone_demo.sh`: a
  `--filter src/` clone holds fewer objects than a full clone (both by
  object-store count and `sc verify`'s gap report), docs/lib/ are never
  fetched or materialized, a src/ edit committed and pushed from the
  partial clone lands cleanly (an independent full re-clone sees the edit
  AND byte-identical docs/lib), `sc backfill docs/` shrinks the gap count
  and makes docs/ genuinely readable, and `sc gc` on the partial clone
  succeeds and preserves everything — run twice, zero residue. (ADR-0037.)

- **Phase 28 — Security hardening sweep.** The P25–P27 scale-&-reach
  horizon surfaced a wire attack surface (a hostile `UpdateRef` over
  ssh/http) that never got a dedicated closing pass; a 2026-07-09 security
  audit's four fix-now findings close it, security-only, no new feature
  axis. Ref-name validation: `refs::write_branch_tip`/`read_branch_tip`
  now call the existing strict `validate_branch_name` — the one choke
  point every local-branch write reaches (CLI, the wire `UpdateRef` arm,
  undo, ws) — and `is_unsafe_ref_component` (the distinct, `/`-permitting
  remote-tracking validator) is upgraded to also reject whitespace/control,
  closing an oplog-corruption gap via a hostile git remote's branch name.
  DoS caps: a single `MAX_OBJECT_SIZE` (256 MiB) in `crates/core` bounds
  the wire frame length, the pack-record compressed length, AND the zstd
  decompressed output via a decode-WITH-LIMIT reader (never decode-then-
  check, so a decompression bomb never fully materializes); four
  object-decode count sites switch from a raw length read to the existing
  `Reader::count()` guard. `sc protect` equality nudge: a filename-only
  `looks_like_low_entropy_secret` heuristic (deliberately distinct from
  the P5 content scanner) prints one stderr warning steering low-entropy
  secret basenames (`.env`/`*.key`/`*credentials*`…) toward `sc secret`,
  citing ADR-0014 — warning-only, convergent encryption's
  equality-confirmability stays accepted by design. Secret env-var
  boundary: the threat model is tightened to "authorized local process
  context, NOT strong isolation," and a compile-time pin locks in that
  `scl_crypto::open`'s `Zeroizing<Vec<u8>>` plaintext rides unchanged to
  the unavoidable `OsString` child-env hand-off — the parent's buffer
  zeroizes on drop, the child-env copy is fundamental and un-zeroizable.
  Every prior demo stays green plus new pinned regression tests; no new
  dependency. (ADR-0039.)

- **Phase 29 — sc+http access control.** The second, larger half of the
  security horizon: P26 shipped `sc serve --http` unauthenticated and
  unrestricted, the audit's remaining High. P29 closes it with three
  composed gates, dep-free throughout. A fail-closed non-loopback bind:
  refused unless justified by `--read-only`, `--allow-public`, or ≥1
  configured serve token; loopback always binds. Bearer-token auth at the
  HTTP opening: once `.sc/serve-tokens.toml` holds ≥1 token, a valid
  `Authorization: Bearer` is required on every connection, loopback
  included — `read_client_opening` returns the presented token,
  `handle_http_connection` constant-time-compares `BLAKE3(presented)`
  against stored hashes and writes `401` before the `200`/wire handoff on a
  miss; `sc serve token add/remove/list` mint/drop/list `sct-<hex>`
  (256-bit) tokens as `{label, hash, scope}`, the raw value printed once and
  never persisted, presented by the client via `SC_HTTP_TOKEN`. Per-connection
  read-only enforcement: `--read-only` (a floor an `rw` token cannot
  elevate) or a matched `ro`-scope token routes the connection into
  `wire::serve_with_policy`, which rejects `PutObject`/`PutPack`/`UpdateRef`
  before any store write via a new `EC_READONLY` wire error. A review fix
  closed a fail-open: a non-loopback bind justified only by tokens now fails
  closed (`401`, not an open server) if its last token is removed while
  running. The wire format is unchanged but for the new error code, so the
  ssh path stays untouched; `PROTOCOL_VERSION` stays 3; no new dependency,
  no TLS. Proven by `demo/run_http_auth_demo.sh`: a no-token clone is
  rejected with an authentication error, an ro-token clone reads but its
  push is rejected read-only, an rw-token push lands and a later ro-token
  clone sees it, an unjustified `0.0.0.0` bind is refused while
  `--allow-public` opens it deliberately, and zero `.sc/tmp` residue is left
  anywhere — the P26/ssh/streaming demos stay green unchanged. Closes the
  security horizon (P28 + P29). (ADR-0040.)

- **Phase 30 — agent session transcripts.** The opening move of the
  agent/workspace-depth horizon: a `Transcript { snapshot, agent, session,
  nonce, ciphertext, wrapped_keys }` CAS object (`TAG_TRANSCRIPT`,
  bytes-only in `crates/core` — the crypto quarantine holds) lets `sc
  transcript attach <ref> <file> [--agent <name>] [--sign] [--identity
  <key>]` seal an agent-session body to a commit's tip snapshot, reusing
  `scl_crypto::seal`/`open` verbatim (a fresh per-attach DEK wrapped per
  recipient, `TAG_SECRET` shape) so plaintext never enters the CAS — a
  keyless clone gets ciphertext only. A one-to-many `.sc/transcripts`
  index (snapshot → transcript ids) means `amend`/`rebase`/`merge` start a
  new snapshot with none attached — no silent carry-forward of stale
  provenance. Signing is opt-in (`sc transcript sign`/`--sign` at attach)
  under a `"sc-transcript-sig-v1"` domain, sharing P22's `SignatureObj` and
  `.sc/signatures` index verbatim — no second index, no format change —
  with the same four-state trust precedence. Transfer needed zero wire
  changes: the sender over-sends indexed transcript ids into the want-set
  (has-gated) and the receiver reindexes idempotently, adopting the P22
  refetch-fix discipline; a final-review Critical caught that the SAME
  discipline had a gap of its own — a transcript's own signature is keyed
  by the transcript's id, not its snapshot's, so the original over-send
  (queried over snapshot ids alone) silently dropped a signed transcript's
  signature on clone/fetch/push, landing it `Unsigned` on the far side.
  Fixed by folding transcript ids into the signature query at both sender
  seams (`get_pack`, `push`), pinned by a new regression test. `sc gc`
  roots live transcript ids BEFORE `signatures::gc_prune` runs (the same
  ordering discipline P22's signature index needed), so a signed
  transcript's signature survives exactly when the transcript itself does;
  a transcript whose only snapshot goes unreachable is pruned with it. `sc
  export --to <git-repo>` drops transcripts (no Git-native form) and
  reports a `transcripts_dropped` count. `sc ws harvest --transcript <path>
  [--sign]` attaches one transcript per landed workspace. `sc log` renders
  an index-only presence marker (`transcript: N` / `transcript: N ✓`) that
  never decrypts. Accepted boundaries: the body is opaque (no schema,
  agent-agnostic); sealed-by-default (no plaintext-transcript escape
  hatch); no access-lifecycle (rewrap/grant/revoke) and no deletion in the
  MVP. Proven by `demo/run_transcript_demo.sh`: attach + sign, a plain `sc
  clone` carrying the transcript, a wrong-identity `sc transcript show`
  failing closed on ciphertext while the right identity decrypts the exact
  body bytes, the `sc log` marker, and `sc gc` pruning a deleted branch's
  transcript while the still-reachable one survives — run twice, zero
  residue. No new dependency. (ADR-0038.)

- **Phase 32 — In-binary TLS (`sc+https://`).** Closes the audit's High #1
  (plaintext bearer tokens/traffic on `sc+http://`) and ADR-0036's "no TLS"
  boundary. A new leaf crate, `crates/tlsio` (`scl-tlsio`), is the only crate
  linking rustls (0.23, ring provider, `default-features = false` —
  ~14 new crates, C compiler only, no cmake) and rcgen; `repo` is its sole
  consumer, extending the dependency rule to
  `cli → repo → {vfs, gitio, crypto, tlsio} → core`. Two seam functions grow
  a TLS wrap and nothing else changes — the opening codec, `wire.rs`, and
  `serve_tokens.rs` are byte-for-byte unchanged, `PROTOCOL_VERSION` stays 3.
  Trust is accept-new TOFU (the SSH `known_hosts` shape): the client pins
  `SHA-256(SPKI)` into `~/.config/sc/known_hosts` on first connect
  (`SC_HTTPS_KNOWN_HOSTS` override, `SC_HTTPS_FINGERPRINT` pre-pin,
  `SC_HTTPS_STRICT=1` to refuse unknown hosts); pinning is pin-only in v1
  (names/validity ignored) but the handshake signature is still verified, and
  a pin mismatch always hard-fails. `sc serve --http <addr> <path> --tls
  [--tls-cert <pem> --tls-key <pem>]` auto-mints a self-signed identity into
  `.sc/serve-tls/` (key `0600`, key-is-identity) unless PEM is supplied;
  `sc serve fingerprint [<path>]` mints-if-missing and prints the SPKI
  fingerprint for out-of-band distribution. **Gate change (breaking):** a
  non-loopback bind now needs `--read-only`, `--allow-public`, or (`--tls`
  AND ≥1 token) — P29's "tokens alone justify a public bind" is narrowed,
  since a token protecting only a plaintext channel was never the guarantee
  its wording implied. **Deliberate spec deviation:** under TLS, the
  `--max-connections` busy-shed at the connection cap closes the socket
  silently instead of writing a readable `503`, because a readable status
  would require a TLS handshake on the accept thread, violating ADR-0041's
  accepts-never-block property; plaintext connections keep the readable
  `503` unchanged. Proven by `demo/run_tls_demo.sh`: a TLS round trip
  carrying a signed chunked blob byte-for-byte, the TOFU
  pin/mismatch/strict/pre-pin lifecycle, and the tightened plaintext gate —
  run twice, zero residue. (ADR-0042.)

## Active

**None.** The agent/workspace-depth horizon opened by P30 is complete; P32
closed the standalone TLS gap the P25–P31 horizon left open; the next
horizon is TBD.

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
| **P25 — Streaming pack transfer (bounded-RAM, >4 GiB)** | `push`/`fetch`/`clone` over ssh:// don't hold a whole pack in RAM anywhere — server, wire, or client | `PackWriter`/`parse_pack_reader` (bounded-RAM pack build/parse); `ST_PACK_CHUNK`/`ST_PACK_END` chunk framing (`SC_PACK_CHUNK`-tunable); `PROTOCOL_VERSION` 2, v1 dropped; two-pass atomic-after-verify ingest + `TempPackGuard`; the ssh client's own `sync.rs` fetch/push call sites route through the same `ingest_pack_file`/`write_ids_to_temp_pack` machinery (final-review fix); proven by `demo/run_streaming_demo.sh` (forced 4 KiB chunks, byte-for-byte clone, signature rides the stream, zero temp residue) | [0035](docs/adr/0035-streaming-transfer.md) |
| **P26 — sc-native HTTP transport** | Reach a repo over plain TCP with no ssh account | `sc serve --http <addr> <path>`; `sc clone sc+http://host[:port]/repo`; thread-per-connection server, opening-status mapped before the wire handshake, P25 chunk stream + P22 signatures ride the raw socket with no HTTP framing; proven by `demo/run_http_remote_demo.sh` (real loopback TCP, no shim; clone/push/fetch byte-for-byte, signed commit verifies clean, zero `.sc/tmp` residue) | [0036](docs/adr/0036-http-transport.md) |
| **P27 — Partial clone** | Bound network transfer to a subset of paths, not the whole repo | `sc clone --filter <prefix…> <src> <dst>` fetches only in-filter objects (`.sc/promisor` + filtered reachability walk); `sc backfill <prefix…>` widens on demand; `sc gc`/`sc verify` are gap-tolerant; merge/rebase/`ws harvest`/`sc work`/`sc export` refuse on a partial clone; proven by `demo/run_partial_clone_demo.sh` (fewer objects fetched, push composes after a partial-clone commit, backfill shrinks the gap count, gc preserves everything, run twice) | [0037](docs/adr/0037-partial-clone.md) |
| **P28 — Security hardening sweep** | Close the audit's concrete-bug Highs + surface the accepted Mediums | strict ref-name validation at the write/read boundary (hostile wire `UpdateRef` + git-remote branch names rejected); `MAX_OBJECT_SIZE` caps every untrusted frame/pack-record/zstd-output length; `sc protect` nudges low-entropy secret filenames toward `sc secret`; secret env-var boundary documented as authorized-local-process-context + plaintext stays `Zeroizing`; every prior demo green + new pinned regression tests, no new dependency | [0039](docs/adr/0039-security-hardening-sweep.md) |
| **P29 — sc+http access control** | Close the audit's remaining unauthenticated-server High | fail-closed non-loopback bind; `sc serve token add/remove/list` + `SC_HTTP_TOKEN` bearer auth at the HTTP opening (constant-time `BLAKE3` compare, `401` before the wire handoff); `--read-only`/`ro`-scope tokens reject mutating verbs before any store write via `EC_READONLY`; proven by `demo/run_http_auth_demo.sh` | [0040](docs/adr/0040-sc-http-access-control.md) |
| **P30 — Agent session transcripts** | Attach a sealed, provenance-checked agent-session record to a commit | `sc transcript attach <ref> <file> --agent claude --sign`; a keyless clone gets ciphertext only, the recipient's identity decrypts byte-exact; `sc log` shows a non-decrypting presence marker; `sc gc` prunes a transcript once its only snapshot is unreachable; proven by `demo/run_transcript_demo.sh` | [0038](docs/adr/0038-agent-session-transcripts.md) |
| **P31 — Listener resource limits** | Bound `sc serve --http`/`--stdio` against a hostile or overloaded peer | `--max-connections`/`--timeout`/`--max-pack-size` close ADR-0036's three named-but-open accepted consequences plus an aggregate-pack-spool gap this phase's own research pass found; busy-status-and-close at the connection cap, connection-fatal session timeout, `EC_TOO_LARGE` mid-stream abort on both transports, capped read-only pre-drain, Go-shaped exponential accept backoff; proven by `demo/run_limits_demo.sh` plus unit-test-proven timeout/backoff | [0041](docs/adr/0041-listener-resource-limits.md) |
| **P32 — In-binary TLS (`sc+https://`)** | Confidential `sc+http` transport without a reverse proxy | `sc serve --http <addr> <path> --tls` auto-mints (or loads PEM) a serve identity; `sc clone sc+https://host/repo` with accept-new TOFU pinning into `~/.config/sc/known_hosts`; gate tightened so a plaintext public bind can no longer be justified by tokens alone (`--tls` + ≥1 token now required); proven by `demo/run_tls_demo.sh` (signed chunked blob over TLS, pin/mismatch/strict/pre-pin, tightened plaintext gate) | [0042](docs/adr/0042-in-binary-tls-sc-https.md) |

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
sparse checkouts → P24, streaming (>4 GiB) wire frames → P25, sc-native
HTTP transport → P26, and partial clone → P27 — this closes the P25–P27
scale-&-reach horizon):

- **Unbounded thread-per-connection in `sc serve --http` (P26).**
  `serve_http_listener` spawns one OS thread per accepted socket with no
  pool, cap, or backpressure — a connection-churn client can exhaust
  server threads/fds. A bounded connection pool is the follow-on.
- **No idle-transfer watchdog in `sc serve --http` (P26).** The
  opening-read timeout is cleared once `wire::serve` takes over, so a
  client that completes the opening and then stalls mid-transfer holds
  its thread indefinitely. An idle-transfer watchdog distinct from the
  opening-read timeout is the follow-on.
- **No accept-loop backoff in `sc serve --http` (P26).** A sustained
  `EMFILE`/`ENFILE` (fd exhaustion) makes the accept loop hot-spin on
  back-to-back errors instead of backing off. Bounded backoff on repeated
  accept errors is the follow-on.
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
- **Sparse-gate the conflict helper's non-marker writes (P24 boundary).**
  `Repo::materialize_conflict_state` gates conflict *markers* against the
  sparse spec but not its `to_encrypt`/sidecar write loops — so an
  in-sparse conflict co-occurring with an out-of-sparse protected/I2 clean
  change transiently writes that out-of-sparse plaintext to disk outside
  the view, and it PERSISTS after completion until a later re-lay (only
  abort cleans it). Not data loss (completion re-lands it in the CAS) and
  not a disclosure (an authorized identity produced it), documented in
  ADR-0034 — but the sparse view is briefly wider than advertised. Extend
  the gate to those write loops.
- **Sparse ergonomics (P24 final-review Minors).** A bogus/no-match
  `sc sparse set <prefix>` empties the working tree with no warning
  (recoverable via disable); a zero-arg `sc sparse set` silently equals
  `disable`; blank lines in a hand-edited `.sc/sparse` want tolerant
  parsing. Small usability hardening.
- **Transparent lazy-fetch for partial clones (P27).** `sc backfill` is
  explicit-only by design (ADR-0037's "no network in read paths" choice);
  the identical filtered-walk/gap infra could instead dial the promisor
  origin automatically on any gap, matching git's promisor default. Real
  scope/risk (offline breakage, surprise latency, fetch-during-gc), so it
  stays deferred, not accidentally missing.
- **Per-case gap-tolerant merge/rebase/ws-harvest/sc-work on a partial
  clone (P27).** These are refused entirely today
  (`Error::PartialCloneUnsupported`) rather than gap-tolerantly
  reimplemented — a deliberate MVP coarsening, not a technical ceiling.
  Threading gap-tolerance through `three_way`/replay/`ws::harvest`
  individually is the follow-on if the "backfill to a full clone first"
  workaround proves too coarse in practice.
- **Blob-size/object-count clone filters (P27).** `sc clone --filter` is
  prefix-only, matching the sparse path-boundary machinery already built;
  git's `--filter=blob:limit` size-based filtering is a separate axis,
  deferred.
- **Randomized protected mode (P28).** `sc protect` stays convergent
  (deterministic DEK/nonce per plaintext), so ciphertext equality still
  confirms plaintext equality without decryption — accepted by design in
  ADR-0014, surfaced rather than closed by P28's filename nudge. A
  non-convergent DEK/nonce mode for equality-hiding on high-sensitivity
  paths is the follow-on.
- **fd/stdin secret injection (P28).** `sc run` hands decrypted secrets to
  the child via its environment — observable by same-user processes,
  crash dumps, and shell wrappers, per the tightened threat-model wording.
  An alternative injection path (an fd or stdin the child reads instead of
  inheriting an env var) would shrink that exposure and is deferred.
- **`--max-object-size` operator config knob (P28).** `MAX_OBJECT_SIZE`
  (256 MiB) is a compile-time constant anchoring every untrusted-length
  guard; letting an operator raise or lower it per-deployment is deferred.
- **P28 review follow-ons.** A whole-branch final review of the P28
  security sweep closed the one real client-side DoS gap
  (`wire::decode_refs_body`'s fabricated-count allocation) and corrected
  stale docs, but named four small non-blocking items, deferred rather
  than silently dropped: `refs::write_head`/`refs::delete_branch` gaining
  a one-line `validate_branch_name` call for ref-validation class
  completeness (not exploitable today — `HEAD`'s path is fixed and
  `delete_branch` only takes internally-generated names); an
  `SC_PACK_CHUNK` upper-clamp to `MAX_OBJECT_SIZE` (an oversized chunk
  config today produces frames the receiver's cap rejects — a
  self-inflicted confusing failure rather than a clear one);
  `Repo::worktree_paths` doing a paths-only walk instead of loading every
  file's full bytes; and extracting a shared `path_under_prefix(path,
  prefix)` helper so `run_protect`'s `/`-boundary filter and
  `protect.rs::matching_prefix` stop duplicating the same rule.
- **Per-path/per-ref ACLs (P29).** `sc serve --http` access control is
  all-or-nothing per connection (`ro`/`rw`); scoping a token to specific
  path prefixes or refs is beyond the MVP. Deferred.
- **Token expiry/rotation metadata (P29).** `sct-` tokens have no expiry
  field; rotation today is add-new + remove-old with no automation or
  reminder. Deferred.
- ~~**`sc+https://` / TLS (P29).** `sc serve --http` is plaintext-only; a
  bearer token crosses the wire in cleartext, so a public deployment must
  front with a TLS reverse proxy today. A first-party TLS dependency is
  deferred, against the P25/P26 dep-free grain.~~ **Done.** Shipped in P32
  (ADR-0042): `sc+https://` via in-binary rustls, accept-new TOFU pinning,
  a narrowed non-loopback bind gate (`--tls` + token, not token alone). See
  the Phase 32 entry above. Follow-ons this phase named rather than closed:
  CA-path validation as an additive trust option for PEM-provisioned
  deployments (v1 is pin-only, names/validity ignored); opt-in SNI/
  certificate-name validation; pin-management UX (`sc tls` list/remove
  entries in `~/.config/sc/known_hosts` — today only `sc serve fingerprint`
  and first-connect/`SC_HTTPS_FINGERPRINT` write pins, nothing removes one);
  TLS session-resumption knobs (not evaluated this phase — a later
  throughput pass if repeated short-lived connections to the same host prove
  handshake cost material).
- ~~**Full OS-assigned-port de-flake for the CLI http-serving tests
  (launch prep).**~~ **Done.** `sc serve --http` now announces its bound
  address on stdout (`listening on <addr>`) right after `TcpListener::bind`
  — stdout is free in `--http` mode (the wire protocol rides the TCP
  socket, unlike `--stdio`). `serve_http_cli_answers_on_socket` and
  `serve_http_read_only_flag_flows_through` bind `127.0.0.1:0` and read the
  OS-assigned port back from that line (which doubles as the readiness
  signal), eliminating the pid-derived fixed port entirely. The launch-prep
  investigation also surfaced the true root cause of the historical flake:
  a lone `stream.read()` for the `HTTP/1.1 400` assertion returned as soon
  as the first TCP segment arrived, so under load it split off just
  `HTTP/1.1 ` before `400 Bad Request` — now read to EOF.
- **Tighten the workspace clippy allow-list (launch prep).** CI runs
  `clippy --all-targets -D warnings`; `[workspace.lints.clippy]` in the root
  `Cargo.toml` allows a curated set (`type_complexity`, `too_many_arguments`,
  `doc_lazy_continuation`, and three cosmetic style lints) that are deliberate
  design or cosmetic in reviewed code. Revisit whether any should be fixed at
  the source and removed from the allow-list.
- **CodeQL / SAST workflow (launch prep).** A CodeQL security-scanning
  workflow (as the sibling `git.agentic` has) was left out of the initial
  launch because CodeQL's Rust support is newer; add it once verified not to
  red-X, so the security posture is scanned as well as documented.
- **Coordinated RustCrypto-stack major-version migration (post-launch).** The
  crypto/RNG stack (`x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`,
  `sha2`, `hkdf`, `rand_core`/`rand_chacha`) is tightly version-coupled — a
  single-crate major bump breaks compilation, so Dependabot is configured to
  skip majors on these (minor/patch security updates still flow). Migrating the
  whole stack to current majors is a deliberate, tested pass, not an automated
  bump; likewise `toml` 0.8 → 1.x and any pinned-toolchain bump.
- **`404`-before-auth repo-presence oracle (P29).** `handle_http_connection`
  checks `.sc/` presence before the bearer-auth gate, so an unauthenticated
  client can distinguish "repo here, need a token" (401) from "no repo here"
  (404) — a minor information leak, not a read/write bypass. Deferred.
- **`--transcript auto` probing (P30).** `sc ws harvest --transcript
  <path>` requires an explicit path today; auto-discovering a
  conventional transcript location (e.g. an agent-runner-written temp
  file) per workspace is deferred.
- **`sc transcript drop` + resurrection tombstone (P30).** There is no
  command to remove an attached transcript short of gc-by-unreachability;
  a first-class drop with a tombstone (so a later merge of a pre-drop
  branch can't silently resurrect it, mirroring P16's revocation
  tombstones) is deferred.
- **Transcript access lifecycle (P30).** Transcripts have no
  rewrap/grant/revoke surface — sealed once, to the recipient set at
  attach time, permanently. Extending P17's rewrap and P16's
  grant/revoke machinery to transcripts is deferred.
- **`--no-transcripts` transfer knob (P30).** `fetch`/`clone`/`push`
  always carry every indexed transcript covering a transferred snapshot;
  an opt-out for bandwidth- or exposure-sensitive transfers is deferred.
- **`sc export --transcripts=entire` (P30).** Git export unconditionally
  drops transcripts (reported via `transcripts_dropped`); an opt-in mode
  that carries them as detached Git notes or a sidecar format is
  deferred.
- **Per-turn live checkpointing (P30).** `sc transcript attach` is a
  whole-session, after-the-fact seal; incremental per-turn attachment
  during a live agent session (rather than one file at the end) is
  deferred.
- **P30 review follow-ons.** The final-review pass that caught the
  transcript-signature transfer Critical (see the Phase 30 entry above)
  also named four small non-blocking items, deferred rather than
  silently dropped: threading `--transcript`/`--sign` through
  `Repo::ws_harvest` itself instead of the current CLI-side post-harvest
  seam in `main.rs`; `sc transcript list` with no `<ref>` walking the
  full DAG (every parent) rather than only the first-parent mainline
  `sc log` follows, so a transcript attached on a merged-in side branch
  can go unlisted; a `transcripts_ride_ssh_transport` wire-harness test
  twin of the local-transport transfer tests, since the ssh:// path is
  exercised only by the local `Repo::clone_to`/`fetch`/`push` tests
  today; and a one-line fix to `SignatureObj.snapshot`'s now-stale doc
  comment, which still describes the field as always a snapshot id even
  though signing a transcript stores a transcript id there instead.
- **P32 follow-ons.** Four items named but not closed by the P32 TLS work,
  deferred rather than silently dropped: (1) a `.sc`-existence check before
  `sc serve fingerprint`/`--tls` auto-mint — today it happily mints
  `~/.sc/serve-tls` even when run outside a repo; (2) a stderr warning when
  an `SC_HTTPS_*` env knob (`SC_HTTPS_STRICT`/`SC_HTTPS_FINGERPRINT`/
  `SC_HTTPS_KNOWN_HOSTS`) is set but the target URL is plaintext
  `sc+http://` — a scheme-downgrade footgun where the knob silently does
  nothing; (3) a client-side TLS handshake/read timeout — the server bounds
  its side at 30s (the opening read), but the `sc+https://` client is
  unbounded, so this folds into the existing deferred hostile-peer pass
  alongside `read_frame_inner`'s unbounded frame-length allocation; (4)
  `sc remote add` parse-validating `sc+http(s)://` URLs at add time, the
  way `ssh://` already does, instead of deferring the parse to first use.

## How a phase gets built

1. Focused brainstorm for the phase (this skill) → phase spec.
2. `writing-plans` → a task-by-task implementation plan.
3. Subagent-driven (or inline) execution with spec + code-quality review per task.
4. Firm the phase's ADR from **Proposed** to **Accepted**, recording any
   refinements discovered during the build.
