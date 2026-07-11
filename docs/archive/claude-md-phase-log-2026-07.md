# CLAUDE.md phase log — archived 2026-07 (verbatim)

> Extracted verbatim from `CLAUDE.md` (lines 392–1543 as of commit bb6d435,
> P33). The live `CLAUDE.md` now carries a condensed capability map instead;
> authoritative rationale lives in `docs/adr/` and design in `ARCHITECTURE.md`.

## Phase 2 is built

`crates/crypto` (`scl-crypto`) exists and owns all cryptography: envelope
encryption (per-secret DEK under XChaCha20-Poly1305, DEK wrapped per recipient
via X25519 ECDH + HKDF-SHA256), keygen, and a `KeyProvider` abstraction for
loading identities. `Snapshot` carries a `secrets: BTreeMap<String, ObjectId>`
side registry (separate from the file tree) so secrets are env vars, not files
— `checkout` never materializes them. An authorized context decrypts the value
in memory and injects it into a child process environment via `run_with_secret`.
That injection is an authorized local process context, NOT strong isolation:
the decrypted secret is observable by same-user processes, crash dumps, and
shell wrappers through the child environment (P28).

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
recipient re-wrap (`grant`/`revoke`). **(→ P33/ADR-0043: this objection
dissolves for randomized content — a random DEK is independent of the
plaintext, so re-sealing a protected path under a fresh DEK becomes a genuine
cutover; a rotate-for-paths surface is now an unlocked follow-on, recorded not
built.)** `sc secret revoke` remains
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
limitations: 4 GiB frame cap (→ lifted in P25 — packs now stream in
`CHUNK_SIZE` frames, ADR-0035), repo paths with spaces unsupported over real
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
byte-identical). **(→ P33/ADR-0043: no longer unconditionally true — rewrap
now also eagerly re-seals any still-convergent blob RANDOMIZED, changing its
id and the root tree, so a rewrap that upgrades content is content-changing;
only a rewrap over an all-randomized tip stays policy-only.)**
**Skip-and-report:** entries the identity cannot open are
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
↔ sc_id` identity) **→ self-heals in P21** (a mark whose git commit was
pruned from the target — e.g. by `git gc` — is re-verified and
re-synthesized on push/export instead of writing a broken parent chain;
see below). The spawned system `git` binary (`crates/gitio/src/
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
stop-materialized theirs-side-only files as untracked residue **→ closed
in P21** (both now return, and the CLI prints, the protected-skip list
`merge_abort` already reported, so an abort no longer silently drops it).
Proven by
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
across any number of later invocations, even a different day **→ P21**
(`sc ws list` now names a resolved-and-landed workspace `"landed"`, or
`"landed (undone by sc undo)"` if its merge was since undone, instead of
the generic `"abandoned"` a manual `ws_abandon` still shows; see below).
`sc ws
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

**Phase 21 is built.** A hardening sweep closing the P16–P20 review tail,
no new capability axis. Every commit-creating policy op —
`protect`/`grant`/`revoke` (`protect_ops.rs`) and `secret add`/`secret
rotate`/`secret grant`/`secret revoke` (`secrets.rs`, seven ops in all) —
now opens with the same three-line `MergeInProgress`/`PickInProgress`/
`RebaseInProgress` guard block `rewrap` and the ref-movers already used,
closing the P19-I1 hazard (an unguarded policy op mid-stopped-rebase
whose commit the completion machinery silently discarded). A review pass
caught that `secret_grant` needed the same guard as `secret_revoke` —
both call the shared `commit_registry` ref-mover — a Critical fixed
same-day. Marks staleness self-heals at the only dangerous point of use:
`GitTarget::has_object` verifies each mark-reused git commit still
exists in the target before reuse, re-synthesizing (with a one-line
stderr note) when it was pruned instead of writing a broken parent
chain; the check is commit-scoped (not a tree/blob-closure walk) because
`git gc`'s reachability pruning is atomic — a commit is never left
dangling over a pruned tree — and heal convergence is proven to a stable
fixed point, not just a one-shot recovery. Rebase/pick aborts now return
and print the protected-skip list (`merge_abort` parity); `sc status`
distinguishes the resolved-awaiting-`--continue` window from an
unresolved conflict; multi-stop rebase oplog descriptions report
cumulative replayed/skipped counts via two new backward-parsed
`RebaseState` fields. The three verbatim conflict-materialization copies
(merge's conflict arm, cherry-pick's, and the rebase fold's) collapse
into one `pub(crate)` `Repo::materialize_conflict_state` helper under the
P19 extraction discipline — existing conflict tests stay green with zero
test edits. `sc ws list` gains `WsEntry.landed_tip` (backward-parsed,
`None` for pre-P21 manifests) so a resolved workspace that actually
landed a merge reports `"landed"` (or `"landed (undone by sc undo)"` if
its merge is no longer an ancestor of the landing branch's tip) instead
of the generic `"abandoned"` a manual `ws_abandon` still shows; the
listing loop now loads the session manifest once instead of re-parsing
it per workspace. Every closed finding's original repro is a pinned
regression test; the phase's demoable outcome is every existing demo
staying green, not a new demo script. See ADR-0031.

**Phase 22 is built.** Signed commits & provenance. `sc keygen` now emits a
v2 identity: one random seed, HKDF-SHA256-derived (domain strings
`"scl-id-v2-enc"`/`"scl-id-v2-sig"`) into an X25519 encryption key and an
Ed25519 signing key, written as a single `scl-id-<hex>` file; a v1
`scl-sk-` identity still parses and still encrypts, but has no signing
half and errors clearly if asked to sign. Signatures are CAS objects
(`TAG_SIGNATURE`, bytes-only in `crates/core` — no crypto crosses the
quarantine) over the domain-separated snapshot id
(`"sc-snapshot-sig-v1" || id`); a local `.sc/signatures` index maps
snapshot → signature ids, gc-rooted and pruned alongside dead snapshots.
Verification (`sig_status`) is strict four-state: any invalid signature
makes the whole snapshot `Invalid` (checked first, order-independent);
otherwise `Trusted(name)` beats `Untrusted(signer)` beats `Unsigned`.
Surface: `sc commit --sign`/`sc amend --sign` sign the new tip inline;
`sc sign <ref>` retroactively signs any ref's tip (the MVP path for
signing merge/pick/rebase results — re-sign after, rather than threading
`--sign` through every history-editing op); `sc log` renders a
per-commit marker (`signed: name ✓` / `signed: hex… ?` / `signature
INVALID ✗` / nothing when unsigned); `sc verify [<ref>] [--require]`
walks every parent (not just the mainline) and `--require` exits 1 on
anything short of fully trusted. `recipients.toml` gains `[signing]`
(name → `scl-sig-<hex>`) and `[signers] trusted = […]`, mirroring
`[recipients]`'s shape. Transfer needs zero wire changes — signatures
are ordinary objects riding the existing pack; receivers run
`index_incoming` over newly-written ids (`NotFound` there is a hard
error, since the seam's contract is "ids `put_pack` just wrote must
resolve"), and `sc clone` reindexes from a full post-copy object scan
rather than depending on transfer-time bookkeeping. A review-caught
Critical: `fetch` originally skipped resending a signature for a
snapshot the receiver already had, so a signature added upstream
*after* an earlier fetch never arrived on a later re-fetch — fixed by
over-sending every indexed signature for the transfer set, deduped
idempotently on receipt (pinned by
`retroactive_signature_propagates_on_refetch`). Git export/push drops
signatures (no Git-native form exists yet) and reports a
`signatures_dropped` count. `ed25519-dalek` is the only new dependency,
quarantined to `crates/crypto`. **Threat model, stated plainly:**
signing defends against history rewriting in clones/remotes and
attribution disputes; it does NOT defend against a trusted signer acting
maliciously, code quality, or replay of a legitimately signed snapshot
into a different branch position (a signature binds identity to a
snapshot id, not to a branch position) — and `amend`/`rebase`/`merge`
results start unsigned by design, since a new snapshot id is a new
claim. See ADR-0032.

**Phase 23 is built.** Merge ergonomics: `sc conflicts`/`sc resolve` resolve
a conflicted merge/pick/stopped-rebase without hand-editing markers, on top
of one new abstraction, `conflict_versions(path) -> {base, ours, theirs}`
(`crates/repo/src/conflicts.rs`), that re-derives all three versions from
the DAG for whichever op is active (merge: ours = tip, theirs = MERGE_HEAD,
base = merge-base; pick: theirs = PICK_HEAD, base = its parent — or the
persisted `PICK_MAINLINE_BASE` for a conflicted `--mainline` pick;
rebase-stop: ours = the accumulated tip, theirs = the conflicted commit,
base = its parent) rather than parsing marker text. Each side decrypts
against *its own* snapshot's protection registry; the conflict kind
(text/binary/protected) is classified from tree-entry perms alone, with no
decryption needed. `sc conflicts [<path>] [--identity]` lists conflicted
paths with their kind, or renders one path's `--- base/ours/theirs ---`
sections (plaintext for protected paths, gated on `--identity`); `sc
resolve --ours|--theirs <path…> [--identity]` writes the chosen side's
content to the working file (or deletes it for an absent side), drops the
`.theirs` sidecar this system may have written for a binary conflict — and
only that sidecar, only when `{path}.theirs` isn't itself a tracked file
(a review-caught data-loss bug in an earlier draft blind-unlinked
`{path}.base`/`.ours`/`.theirs` unconditionally; the first two are never
written and removing them was a pure footgun) — and clears the path from
the active conflict record. Resolution only decrypts; it never
re-encrypts, so plaintext still never enters the CAS before the unchanged
`sc commit`/`sc rebase --continue` completion re-encrypts through the
same helpers `commit` always used (encrypting only needs recipient public
keys, so completion needs no `--identity` of its own). `sc status` gained
the same per-path detail under every in-progress banner; `sc status
--json`'s `"conflicts"` field is now `[{path, kind}]` instead of a bare
path list — a strict superset, no existing consumer broke. Whole-file
resolution only — no hunk-level or `--union`/`--base` modes. Proven by
`demo/run_merge_ergonomics_demo.sh`. See ADR-0033.

**Phase 24 is built.** Sparse checkouts: `.sc/sparse` is a local,
uncommitted prefix spec (`sc sparse set <prefix…>`/`sc sparse show`/`sc
sparse disable`; empty/absent = full materialization, matching P7's
`matching_prefix` path-boundary rule). The whole feature is one
generalized carry predicate: `commit`'s existing absent-path carry
(`crates/repo/src/repo.rs`, `snapshot_files`'s carry block — the ADR-0025
P15 discipline) widens from "absent AND still-protected-and-not-a-
recipient" to "absent AND (that OR outside the sparse set)," so a commit
made while narrowed carries the untouched out-of-sparse subtree forward
byte-identical, while an in-sparse absence stays a genuine deletion — the
carried entry's perms byte is the *source* entry's own perms, not a
hardcoded `PROTECTED`, so a carried plain out-of-sparse file doesn't
acquire protection it never had. `materialize` (`crates/repo/src/
worktree.rs`) filters both its write loop and its old-root removal loop by
the spec; `sc sparse set`/`disable` re-lay the working tree on top of the
same function (`old_root = Some(head_root)` narrows or widens against the
current tree). `diff_worktree`/`diff_unified` treat an absent out-of-sparse
path the same as an absent unauthorized-protected one: expected, not a
deletion. A clean merge/pick/rebase change to an out-of-sparse path lands
in the CAS without materializing; a CONFLICT there refuses up front
(`Repo::materialize_conflict_state`, before any marker write) with a "run
`sc sparse set` to include it" hint — `sc resolve` gates the same way,
while `sc conflicts` still inspects freely since it never writes to disk.
`sc sparse set`/`disable` refuse during an in-progress merge/pick/rebase.
`sc ws` workspaces inherit the host repo's sparse view structurally
(threaded into `materialize_workspace` at fork time, and — final-review
fix — the fork-time spec is also PERSISTED in `session.toml` and reused,
never re-read ambiently, so a `sparse set`/`disable` on the host between
fork and harvest cannot reinterpret the workspace's never-materialized
paths as deletions; harvest carries the untouched subtree via the same
generalized predicate). A full-checkout `sc work` agent passes the same
predicate `Sparse::default()`, so its genuine deletions of any path land
instead of being carried against the host's spec. `sc status` shows the
active spec. Sparse CHECKOUT only — every object stays in the CAS
regardless of the spec, so `sc gc`'s reachability walk is unaffected;
partial clone (never fetching out-of-prefix objects) is deferred.
**Boundary:** when an IN-sparse conflict co-occurs with an OUT-of-sparse
protected/I2 clean change in the same merge, that out-of-sparse plaintext
is written to disk outside the sparse view during the conflict window AND
PERSISTS ON DISK AFTER COMPLETION TOO — `materialize_conflict_state`'s
sparse gate covers only its marker-write loop, not its
`to_encrypt`/sidecar-decrypt write loops, and completion does not
materialize. Only abort removes it (its `!sparse.matches` removal arm);
completion's `read_worktree` re-lands the content in the CAS byte-correct
(same as any other carried file) but never deletes the on-disk file — the
plaintext stays on disk until the next materializing operation (`switch`,
`sparse set`/`disable`, another merge) re-lays the tree. This is not data
loss and not a new disclosure (the diff3 content-merge that produced the
plaintext already required an authorized identity; the I2 case is
pre-existing plaintext) —
a bounded disk-hygiene boundary, follow-on to extending the sparse gate to
the `to_encrypt`/sidecar writes too. Proven by `demo/run_sparse_demo.sh`.
See ADR-0034.

**Phase 25 is built.** Streaming pack transfer: `push`/`fetch`/`clone`
over ssh:// no longer hold a whole pack in RAM on the server or the wire.
`crates/core/src/pack.rs` gained an incremental `PackWriter` (appends
objects one at a time to any `Write`, accumulating only the small index in
RAM, byte-identical to `build_pack` for the same object sequence — pinned
by `pack_writer_matches_build_pack_byte_for_byte`) and a streaming
`parse_pack_reader` (verifies each record's BLAKE3 hash off a `Read`
without holding the whole pack body; terminates cleanly on a
record-boundary EOF since the pack format carries no object count).
`crates/repo/src/wire.rs` frames a pack as `ST_PACK_CHUNK`/`ST_PACK_END`
opcodes under the **unchanged** `u32` frame header
(`write_pack_stream`/`read_pack_stream`); `CHUNK_SIZE` defaults to 1 MiB,
overridable per-process via `SC_PACK_CHUNK` (`wire::pack_chunk_size()`) for
tuning or forcing many-chunk transfers in tests/demos. **`PROTOCOL_VERSION`
bumped 1 → 2 and v1 is dropped outright** — there is one pack encoding
(always chunked), and a version mismatch is rejected cleanly at the
`Hello` handshake in both directions; this is a breaking wire change but
acceptable pre-deployment (no old `sc serve` peers in the field). The
sender (`LocalTransport::build_pack_tempfile`) streams objects one at a
time into a temp pack file instead of collecting a
`Vec<(ObjectId, Vec<u8>)>`; the receiver (`ingest_pack_file`) does a
two-pass atomic-after-verify ingest — pass 1 re-reads the spilled file
verifying every record's hash and writing nothing, pass 2 re-reads it
again writing each verified object into the store — so a corrupt or
truncated pack never partially lands, and a hostile per-record length
prefix can only allocate as much as the attacker already transferred
on disk, not an unbounded amount off a live socket. `TempPackGuard`
(`.sc/tmp/`, a new scratch dir — see `Layout::tmp_dir`) is an RAII type
that removes the temp pack file on success or any error alike. Chunk
framing is scoped to the wire boundary only: `LocalTransport` still
passes raw pack bytes end to end, matching the spec's wire-path-only
scope. No new user command — streaming is entirely transparent to every
existing `push`/`fetch`/`clone` invocation; the ssh demo
(`demo/run_ssh_remote_demo.sh`) now streams by construction, and
`demo/run_streaming_demo.sh` forces `SC_PACK_CHUNK=4096` to prove a ~1 MiB
signed blob crosses 250+ chunk frames with the clone byte-for-byte
identical to the origin (object set, working tree, `sc log`) and `sc
verify --require` clean in the clone (proving the signature rode the
chunked stream), with zero `.sc/tmp` residue on either end across two
independent runs. **The client is bounded too (closed in the P25
final-review fix — the headline "bounded RAM on both sides" now holds end
to end, not just server+wire):** `crates/repo/src/sync.rs`'s
`transfer_objects` (shared by `fetch`/`clone_url`) no longer destreams the
whole incoming pack into a `Vec<u8>` — it spills `transport.get_pack`'s
output into a `TempPackGuard`-held temp file and ingests it via
`ingest_pack_file` directly (the same two-pass atomic-after-verify contract
the server already used), peak RAM one object. `Repo::push` no longer
assembles the entire outgoing pack into a `Vec<(ObjectId, Vec<u8>)>` — it
collects only the missing ids and streams them one at a time to a guarded
temp file via a new shared helper, `transport::write_ids_to_temp_pack`
(extracted out of `build_pack_tempfile`'s inner loop so `LocalTransport`'s
remote-side sender and `Repo::push`'s client-side sender share one
ids-to-temp-pack-file implementation), then hands an opened `File` to
`transport.put_pack`. Both temp files are removed on success and every
error path, pinned by `fetch_client_ingests_via_tempfile_zero_residue` and
`push_client_builds_via_tempfile_zero_residue`. One accepted side effect:
a local-path clone/fetch now also spills through a temp file (harmless —
`.sc/tmp` is repo-owned, guard-cleaned scratch). **What remains
unbounded, named honestly:** the in-process `LocalTransport` path within a
single process (a local clone of a >4 GiB repo on the same machine) and
the wire's `read_frame_inner`, which still allocates up to 4 GiB off an
attacker-controlled frame-length header before any chunk boundary is
enforced (pre-existing P12 behavior, deliberately deferred as a
hostile-peer hardening item, not a client-buffering issue). See ADR-0035.

**Phase 26 is built.** A second sc-native network transport alongside P12's
ssh://: `sc+http://host[:port]/repo` (port default `DEFAULT_PORT = 8730`),
parsed by `ScHttpUrl::parse` (`crates/repo/src/http_transport.rs`) —
mirrors `SshUrl::parse`'s error style and additionally rejects a host/path
containing `\r`/`\n` (a CRLF-injection guard, since the opening writer
interpolates them unescaped into the request line/header). The opening
codec is four small, pure `Read`/`Write` functions
(`write_client_opening`/`read_client_opening`/`write_status`/
`read_status`), all routed through one shared `read_bounded_opening`
helper that reads byte-by-byte up to `\r\n\r\n` and errors out once the
accumulator crosses `MAX_OPENING_BYTES` (8 KiB) — a check-before-read
bound, not a fixed-size buffer read, so an unterminated/hostile opening
cannot force unbounded allocation. **Client** `HttpTransport::connect`:
opens a `TcpStream`, writes the opening, then reads and maps the status
line — `200` proceeds, `404` → `Error::NotARepo`, anything else → a clear
protocol error — *before* the `WireClient` handshake begins, so a
non-repo/malformed-response server is never mistaken for a HELLO failure;
the socket is `try_clone()`-split into read/write halves and the status
line is read through the *same* `BufReader` that becomes the `WireClient`'s
reader (not a throwaway clone), since `BufReader` can pull more than one
byte per syscall and a disposable reader risked swallowing the first
wire-protocol frame byte(s). `open_transport` routes `sc+http://` to this
path above the local-path fallback; `ssh://` and P18's `http(s)://`
git-bridge routing are untouched. **Server** `sc serve --http <addr>
<path>`: a `TcpListener`, thread-per-connection — each accepted socket runs
on its own thread via `handle_http_connection`, isolated (a per-connection
error/panic is logged to stderr and never takes down the accept loop or
other connections); `.sc/` missing at `path` → `404` with no wire
handshake attempted; a malformed/oversized opening → best-effort `400`. A
30s read timeout guards the opening read against slow-loris stalls
(byte-bounded by `MAX_OPENING_BYTES` but not time-bounded on its own) and
is cleared right after writing the `200` status, before handing off to
`wire::serve` — a legitimate large streamed pack transfer must not be cut
off mid-stream by the same timeout that guards the opening. Each
connection's thread opens `LocalTransport` fresh — no store or lock is
shared across threads in this module. Concurrency safety is layered: the
pre-existing `.sc/` single-writer `RepoLock` serializes ref updates (the
push's actual commit point), while object writes (`put_object`/`put_pack`)
are lock-free and safe via content-addressed idempotency plus
thread-unique temp sibling names in `atomic_write_durable`
(`crates/core/src/fsutil.rs`, pid + a process-global counter, matching
`TempPackGuard`'s discipline) — a final-review fix, since thread-per-
connection put multiple writers in one process for the first time and the
old pid-only temp name let two threads landing an overlapping object race
on the identical temp sibling. **No double-framing:** after the `200` status, the raw
`TcpStream` goes straight to `wire::serve` — the P25 chunk stream and P22
signatures ride the socket with no HTTP `Transfer-Encoding` wrapper on
either end. Zero new dependencies (`std::net`/`std::io` only — confirmed
by an empty `git diff main -- '*Cargo.toml'`). Proven by
`demo/run_http_remote_demo.sh`: real loopback TCP (no shim needed, unlike
the ssh demo), a ~1 MiB signed blob crosses `sc+http://` clone with
`SC_PACK_CHUNK=4096` forcing many chunk frames, object set/working
tree/`sc log` byte-for-byte identical to the origin, `sc verify --require`
clean in the clone, a push from a second clone lands and a third clone's
fetch sees it, zero `.sc/tmp` residue on either end — run twice.
**Standing boundaries, stated plainly (same class as the ssh transport,
plus one new one):** plaintext only, **no TLS at the time — closed by P32
(ADR-0042)**, which adds `sc+https://` in-binary rather than requiring a
fronting reverse proxy; **no authentication** (`sc
serve --http` is unauthenticated, as `--stdio` delegates auth to ssh —
production auth + TLS means fronting with a reverse proxy; this is the
reach primitive, not a hosted-git competitor); **not HTTP-proxy/CDN safe**
(a strict proxy won't tunnel the post-opening raw protocol, the accepted
cost of the persistent-connection model). **Accepted design consequences at
the time — closed by P31 (ADR-0041):** `serve_http_listener`'s unbounded
thread-per-connection (no pool/backpressure), the opening timeout being
cleared once `wire::serve` takes over (no idle-transfer watchdog), and the
accept loop's lack of backoff on sustained fd exhaustion are all closed by
P31's `--max-connections`, `--timeout`, and hardcoded accept backoff,
respectively — see the P31 section below. See ADR-0036.

**Phase 27 is built.** The P25–P27 scale-&-reach horizon's capstone:
partial clone. `.sc/promisor` (`crates/repo/src/promisor.rs`, local,
uncommitted) records a partial clone's fetch-filter prefixes + the
promisor origin URL; its presence makes a gap expected, its absence means
a full clone with unchanged behavior. `Promisor::matches` is "is this path
itself in-filter" (the P24 `matching_prefix`/`Sparse::matches` boundary
rule, reused verbatim); `Promisor::should_descend` is the load-bearing
second predicate a tree walk needs — whether to descend into a directory
at all, true for an in-filter path OR an ancestor of one (filter
`["src/app/"]` must still walk through `src` to reach `src/app/`, even
though `src` itself never matches). One path-aware walk,
`reachable_objects_filtered` (`crates/repo/src/reachable.rs`) →
`Reachable { included, gaps }`, serves both the server's `get_pack` filter
(a new `GetPack.filter` wire field, `PROTOCOL_VERSION` 2→3 — a v2 peer is
rejected at handshake) and the client's own gc/`sc verify`: a parent tree
is always included, but an out-of-filter child's id lands in `gaps` and is
**never `get()`'d**, which is exactly why a partial clone's absent
out-of-filter objects never surface as errors. A review-caught CRITICAL
fixed pre-merge: expansion dedup had to move from a bare-id gate to a
per-`(id, path)` gate, because content addressing can dedup a
byte-identical subtree to one id reachable at two paths with two different
filter verdicts — a bare-id gate silently dropped whichever path lost the
race. `sc clone --filter <prefix…> <src> <dst>` writes `.sc/promisor` and
`.sc/sparse` to the same prefixes (partial ⊇ sparse — one filter, not two
independent ones); `sc backfill <prefix…>` widens both the fetch from the
promisor origin and the persisted `.sc/promisor` spec, explicitly and
offline everywhere else — no lazy-fetch, no network dialed from inside a
read path. **The original spec claimed "push composes for free via
carry-by-id" — that was false, and this phase corrects the record.**
Building a *new* commit on a partial clone needed real new machinery: the
per-blob byte-carry P24/P15 already had only carries individual absent
blobs, not an entire out-of-filter subtree the working-tree enumeration
never walks in the first place — left alone, that would silently drop
every out-of-filter subtree from the new snapshot. `worktree::
graft_out_of_sparse` closes that gap by splicing the tip's out-of-filter
subtrees back into the freshly built root **by id, never reading their
content**, scoped to a plain single-tip commit (merge/pick completion on a
partial clone is refused outright, not grafted). Only *after* the graft
exists does push's already-filtered reachability walk send just the
client's new in-filter objects while the origin's untouched out-of-filter
objects stay intact — that half of the original claim holds, verified
end to end by a full re-clone after a partial-clone push seeing the edit
AND byte-identical docs/lib. Two review-caught Criticals landed on the
graft: **(C1)** a grafted subtree's PROTECTED blobs never passed through
the encrypt-or-carry loops that populate the new snapshot's wrap map, so
their wrapped DEKs would be silently and *permanently* dropped from every
snapshot built on top — fixed by unioning in every wrap the tip itself
already had (a blanket, not narrowly-scoped, carry-forward — deterministic
but not zero-cost, verified end to end: a full clone decrypts `docs/*`
under the recipient key after a partial-clone-originated commit); **(a
data-safety Critical)** `commit` now REFUSES (`Error::GappedPathContent`,
with a `sc backfill` hint) rather than silently drops any content sitting
under a path this clone never fetched — you cannot commit under an
unfetched subtree, and a stray out-of-filter file on disk blocks even an
otherwise-clean in-filter commit until removed. gc is gap-tolerant by
construction (stops at a gap, never prunes/errors) with a defense-in-depth
backstop: any gap id that happens to be present locally for any reason is
still walked in and retained, so gc never prunes reachable content it
holds. `sc verify` reports `partial: N object(s) outside filter [...]` — a
count, never folded into the trust summary, exit 0 for a healthy partial
clone even under `--require`. **`status`/`diff`/`switch` needed real
gap-tolerant flattener changes, not "zero new code"** — an earlier draft
of this section (and ADR-0037) overclaimed that partial ⊇ sparse made the
existing P24 out-of-sparse diff tolerance sufficient by itself; the
flattener FEEDING that comparison still walked the full unfiltered tree
and had to be bounded by `sparse` up front (`diff_worktree`,
`diff_unified`, `Repo::tracked_paths_at`, and `materialize`'s old-root
removal walk all changed).

**Final whole-branch review (same phase) found one Critical and two
Importants, all closed:** **(C1, one seam over from the subtree-descent
Critical above)** the `(id, path)` fix covered subtree DESCENT but missed
the walk's ROOT push, still gated on a bare id — so a snapshot whose ROOT
tree content-dedups to a subtree an earlier snapshot's walk in the same
call already expanded (the everyday "move everything into `x/`" history)
had its own root walk silently skipped, dropping in-filter content only
reachable via that root's own path — a fresh partial clone silently
missing in-filter objects, corruption by this phase's own definition.
Fixed by hoisting the expansion-dedup set out to span the whole
reachability call and gating the root push on `(root, "")` under a filter
too, mirroring the earlier subtree fix exactly. **(I1)** gc's
walk-what-you-have backstop used the STRICT unfiltered walk, which
`get()`s every child unconditionally — a crash-interrupted `sc backfill`
(Ctrl-C, power loss) can leave a gap-frontier tree present with an absent
child, hard-erroring `sc gc` and violating "gc must never error on a
partial clone." Fixed with a dedicated absence-tolerant walk-in
(`reachable::walk_tree_present_only`) that skips rather than errors on an
absent child; a present object below an absent one is intentionally not
reached and is prunable by the ordinary sweep (gc never prunes reachable
content it *holds* — not literally "structurally incapable of pruning
anything present," which overstated it). **(I2)** `sc backfill <prefix…>`
alone could never actually reach the "backfill to a full clone first"
remedy every guard's error text pointed at — nothing ever removed
`.sc/promisor`. `sc backfill --all` (fetches every remaining object with
no prefix restriction, verifies the closure is genuinely complete, THEN
removes the marker — ordering is load-bearing) is the real escape hatch;
every `PartialCloneUnsupported`/export/`sparse disable` refusal now names
it. `sc ws fork` is also now guarded on a partial clone (it used to
succeed, creating a session `ws harvest` could never land).

**Boundaries, stated plainly:** no network in any read path (fetch is
explicit — `sc clone --filter`/`sc backfill` only); `sc export` refuses
unconditionally on a partial clone (Git needs full trees, no partial
export exists); and, as a deliberate MVP coarsening rather than a
per-case gap-tolerant reimplementation, **merge, cherry-pick/rebase
replay, `sc ws fork`/`sc ws harvest`, and `sc work` are all refused
entirely** on a partial clone (`Error::PartialCloneUnsupported`) — run
`sc backfill --all` to convert to a full clone first. Proven by
`demo/run_partial_clone_demo.sh`: a `--filter src/` clone holds measurably
fewer objects than a full clone (by both raw object-store count and `sc
verify`'s gap report), docs/lib/ are never fetched or materialized, a
src/ edit committed and pushed from the partial clone lands cleanly, `sc
backfill docs/` shrinks the gap count and makes docs/ genuinely readable,
and `sc gc` succeeds and preserves everything — run twice, zero residue.
No new dependencies; `PROTOCOL_VERSION` 3. See ADR-0037.

**Phase 28 is built.** A security hardening sweep closing a 2026-07-09
audit's four fix-now findings — security-only, no new feature axis, no new
dependency. Ref-name validation: `refs::write_branch_tip`/`read_branch_tip`
now call the existing strict `validate_branch_name` (rejects empty,
`.`/`..`, leading-dot, `/`, `\`, whitespace, control) — the one choke point
every local-branch write reaches (CLI, the wire `UpdateRef` arm, undo, ws)
— closing a hostile-wire-client ref-traversal/oplog-corruption gap;
`is_unsafe_ref_component` (the distinct, `/`-permitting validator guarding
remote-tracking `write_remote_tip`) is separately upgraded to also reject
whitespace/control, closing the same class of gap via a hostile git
remote's branch name — two validators, kept distinct on purpose. DoS caps:
a single `MAX_OBJECT_SIZE` constant (256 MiB, `crates/core`) anchors every
untrusted-length guard — the wire frame length (`read_frame_inner`, before
alloc), the pack-record compressed length (`parse_pack_reader`, before
alloc), and the zstd decompressed output via a decode-WITH-LIMIT reader
(never decode-then-check, so a decompression bomb never fully
materializes); the four object-decode count sites (tree entries, snapshot
parents, snapshot secrets, signature wrapped-keys) switch from a raw
length read to the existing `Reader::count()` guard. `sc protect` equality
nudge: `looks_like_low_entropy_secret`, a filename-only heuristic
deliberately distinct from the P5 content scanner, prints one stderr
warning steering a governed low-entropy secret basename (`.env`/`*.key`/
`*credentials*`…) toward `sc secret`, citing ADR-0014 — warning-only,
`sc protect` still proceeds. Secret env-var confidentiality: the threat
model is tightened to "authorized local process context, NOT strong
isolation," and a compile-time pin locks in that `scl_crypto::open`'s
`Zeroizing<Vec<u8>>` plaintext rides unchanged through to the unavoidable
`OsString` child-env hand-off. **Two accepted boundaries, unchanged by
design:** convergent encryption stays equality-confirmable (ADR-0014 —
**closed for new content in P33/ADR-0043**, which seals all new protected
content randomized; the caveat holds forever for pre-P33 convergent ciphertext
in history — `sc rewrap` only stops it propagating into future snapshots,
rotation ≠ erasure per ADR-0019); the secret's child-env
copy is fundamental and un-zeroizable (fd/stdin injection is deferred, not
a bug) — the parent's own decrypted buffer is what gets zeroized. Every
prior demo stays green plus new pinned regression tests across all four
fixes. Accepted boundary: `MAX_OBJECT_SIZE` guards the transfer path only
(`parse_pack_reader`, `read_frame_inner`), not local `commit`/`Store::put`,
so a >256 MiB local blob commits fine but fails every subsequent
push/fetch/clone at the receiver's cap. **Final-review fix wave (same
phase):** the client-side `ListRefs` DoS gap — a hostile server's response
could claim a fabricated `u32` count and drive a `Vec::with_capacity`
allocation on the client before validating any entry, the same class
`Reader::count()` already closed for object decoding — is closed by the
same guard, `Cur::count()`, applied to `wire::decode_refs_body`. See
ADR-0039.

**Phase 29 is built.** `sc serve --http` gains three composed access-control
gates, closing the security horizon's remaining unauthenticated-server
High — security-only, no new dependency, no TLS. A fail-closed non-loopback
bind: refused unless justified by `--read-only`, `--allow-public`, or ≥1
token in `.sc/serve-tokens.toml`; loopback always binds. Opt-in bearer auth
at the HTTP opening: once ≥1 token is configured, a valid `Authorization:
Bearer` is required on every connection including loopback (`401` before the
`200`/wire handoff), verified by a constant-time `BLAKE3` compare against
`sct-<hex>` (256-bit) tokens stored as `{label, hash, scope}` — the raw
token prints once and is never persisted; the client presents it via
`SC_HTTP_TOKEN`. Per-connection read-only enforcement: `--read-only` (a
floor an `rw` token cannot elevate) or an `ro`-scope token routes the
connection into `wire::serve_with_policy`, which rejects
`PutObject`/`PutPack`/`UpdateRef` before any store write via a new
`EC_READONLY`. A review fix closed a fail-open: a non-loopback bind
justified only by tokens now fails closed (`401`, not an open server) if its
last token is removed while running. **Accepted boundaries at the time —
closed by P32 (ADR-0042):** no TLS — a bearer token crossed the wire in
plaintext, so a public deployment had to front with a TLS reverse proxy
(`sc+https://` deferred); loopback with no tokens configured stays
unauthenticated by design, for local-dev ergonomics, unchanged by P32. **Note
also:** P32 narrows this phase's non-loopback bind gate — tokens alone no
longer justify a *plaintext* public bind; a non-loopback bind now needs
`--read-only`, `--allow-public`, or (`--tls` AND ≥1 token). Wire-unchanged but
for `EC_READONLY`; `PROTOCOL_VERSION` stays 3; ssh `--stdio` is untouched.
Proven by `demo/run_http_auth_demo.sh`. See ADR-0040.

**Phase 30 is built.** Agent session transcripts: a sealed provenance
record for an agent's session can now attach to a commit. `Transcript {
snapshot, agent, session, nonce, ciphertext, wrapped_keys }` is a
bytes-only `TAG_TRANSCRIPT` object in `crates/core` — the crypto
quarantine holds — whose body is ALWAYS sealed via `scl_crypto::seal`
(a fresh random DEK wrapped per recipient, `TAG_SECRET` shape) before it
ever reaches the CAS, so a keyless clone gets ciphertext only; `open`
reuses `scl_crypto::open` verbatim. A one-to-many `.sc/transcripts` index
(snapshot → transcript ids) means `amend`/`rebase`/`merge` start a fresh
snapshot with none attached — there is no carry-forward of stale
provenance to reason about. Signing is opt-in: `--sign` at attach or a
standalone `sc transcript sign <ref>` signs under a
`"sc-transcript-sig-v1"` domain, sharing P22's `SignatureObj` type and the
SAME `.sc/signatures` index (no second index, no format change) and the
same four-state trust precedence. Transfer needed zero wire changes —
transcripts ride the existing pack: the sender over-sends every indexed
transcript covering a transfer-relevant snapshot into the want-set
(has-gated, never subtracted from what the receiver already has) and the
receiver reindexes idempotently, adopting the P22 refetch-fix discipline
verbatim. **A final-review Critical found the same discipline had a gap
of its own:** a transcript's own signature is keyed by the transcript's
id, not its snapshot's, but the sender's signature over-send queried
`indexed_signature_ids_for` over snapshot ids alone — so a `sc transcript
attach --sign` rode the pack correctly as an object but landed
`Unsigned` on the far side, silently dropping its provenance on every
clone/fetch/push. Fixed at both sender seams
(`LocalTransport::build_pack_tempfile`'s `get_pack` path and
`Repo::push`) by folding the transcript ids into the signature query
before extending `want_set`, pinned by
`signed_transcript_signature_rides_the_pack`. `sc gc` roots live
transcript ids into `reachable` BEFORE `signatures::gc_prune` runs — the
same ordering P22's own signature index needed — so a signed
transcript's signature survives exactly when the transcript itself does;
a transcript whose only snapshot goes unreachable (e.g. its branch is
deleted) is pruned along with it, while a still-reachable transcript
survives the same gc, repacked like any other object. `sc export --to
<git-repo>` drops transcripts outright (no Git-native form exists) and
reports a `transcripts_dropped` count. Surface: `sc transcript
attach/show/list/sign`, `sc ws harvest --transcript <path> [--sign]
[--identity <key>]` (one transcript per landed workspace), and an
index-only `sc log` presence marker (`transcript: N` / `transcript: N
✓`) that never decrypts. **Accepted boundaries:** the body is opaque —
no schema, agent-agnostic; sealed-by-default, so a keyless clone always
gets ciphertext with no plaintext escape hatch; no access-lifecycle
(rewrap/grant/revoke) and no deletion in the MVP — a transcript is sealed
once, to the attach-time recipient set, permanently, until its snapshot
becomes unreachable. Proven by `demo/run_transcript_demo.sh`: attach +
sign, a plain `sc clone` carrying the transcript (object AND its
signature, post-fix), a wrong-identity `sc transcript show` failing
closed on ciphertext while the right identity decrypts the exact body
bytes, the `sc log` marker, and `sc gc` pruning a deleted branch's
transcript while the still-reachable one from earlier survives — run
twice, zero residue. No new dependency. See ADR-0038.

**Phase 31 is built.** Listener resource limits close ADR-0036's three
named-but-open accepted consequences plus a fourth this phase's own
research pass (`docs/research/bounded-server-patterns.md`, ticket #27)
found and named for the first time: the aggregate incoming-pack spool was
unbounded on both transports, including via the read-only rejection path.
`sc serve --http` gains `--max-connections <n>` (default 32, matching
`git-daemon`, 0 = unlimited; at the limit a new connection gets an
immediate busy status at the pre-handshake opening seam and closes — no
queuing), `--timeout <secs>` (default 300, 0 = disables; read+write
timeouts now persist for the whole session rather than being cleared after
the opening, and a trip is connection-fatal since mid-stream abort desyncs
the frame stream; the opening keeps its own unchanged 30s), and
`--max-pack-size <bytes>` (default 16 GiB, 0 = unlimited, floor 256 MiB =
`MAX_OBJECT_SIZE`; applies to **both** `--http` and `--stdio` since it
lives in the shared `WirePolicy`, not the `--http`-only `ServeLimits`; a
counted mid-stream abort replies `EC_TOO_LARGE` best-effort before closing).
The read-only pre-drain (`wire.rs`'s `EC_READONLY` arm, which drains an
incoming pack before replying so the connection stays in sync) is now
capped at 8 MiB (`RO_DRAIN_CAP`): an honest small misconfigured push still
gets the clean typed error, a larger bulk spool is dropped mid-send instead
of fully written to disk. The accept loop gained a hardcoded Go-`net/http`-
shaped exponential backoff (5ms doubling to a 1s cap, reset on success) —
no operator knob, matching Go's own precedent. Two recorded divergences
from prior art: the timeout ships **on** by default, unlike `git-daemon`'s
off-by-default `--timeout` (a defaults-off knob doesn't close an
audit-tracked High); the pack-spool default is **finite** (16 GiB), unlike
git's unlimited `receive.maxInputSize` (sc servers often share the working
tree's volume). `PROTOCOL_VERSION` stays 3 — none of the four bounds touch
the wire protocol, and `EC_TOO_LARGE` degrades to opaque text on an old
client, same as `EC_READONLY`'s precedent. Zero new dependencies. Proven by
`demo/run_limits_demo.sh` (the floor-cap enforcement on the push path and
the busy-status shed under `--max-connections`); the session-timeout reaper
and accept-backoff pacing are unit-test-proven rather than demo-proven,
since forcing a real stalled socket or fd exhaustion reliably in a demo
script is impractical. See ADR-0041.

**Phase 32 is built.** In-binary TLS: `sc+https://` closes ADR-0036's "no
TLS" boundary and the audit's High #1 (plaintext bearer tokens/traffic). A
new leaf crate, `crates/tlsio` (`scl-tlsio`), is the only crate linking
rustls (0.23, `default-features = false`, features `ring, std, tls12,
logging` — ~14 new crates, C compiler only, no cmake), rcgen, and `ring`
(digest only, for the SPKI fingerprint — the RustCrypto quarantine in
`crates/crypto` is untouched); `repo` is its sole consumer, extending the
dependency rule to `cli → repo → {vfs, gitio, crypto, tlsio} → core`. Two
seam functions grow a TLS wrap and nothing else changes: client
`HttpTransport::connect` wraps the `TcpStream` before `write_client_opening`
when the URL is `sc+https://`; server `handle_http_connection` wraps before
`read_client_opening` when `--tls` is set — the opening codec, `wire.rs`, and
`serve_tokens.rs` are byte-for-byte unchanged, `PROTOCOL_VERSION` stays 3.
Trust model is accept-new TOFU, the SSH `known_hosts` shape: the pin is
`SHA-256(SPKI DER)`, stored one `host:port sha256:<hex>` line per host in
`~/.config/sc/known_hosts` (`SC_HTTPS_KNOWN_HOSTS` overrides the path);
`SC_HTTPS_FINGERPRINT` pre-pins without persisting (CI); `SC_HTTPS_STRICT=1`
refuses an unknown host outright (`=1` enables it; any non-empty value other
than `0` is also treated as enabled — fails closed on a typo). Pinning is
deliberately pin-only in v1 —
certificate names/validity are ignored — but the handshake signature is
still verified, so a captured cert replayed without its private key is
rejected even against a matching pin; a pin mismatch always hard-fails, never
prompts. Server: `--tls` (refused together with `--stdio`) auto-mints a
self-signed identity into `.sc/serve-tls/` (`cert.pem`/`key.pem`, key file
`0600` — the key IS the server's identity — regenerated only if missing,
`not_after` 2126) unless `--tls-cert`/`--tls-key` PEM is supplied; the
startup banner's second line and `sc serve fingerprint [<path>]` (mints if
missing) print the SPKI fingerprint an operator distributes out-of-band
before a client's first connect. **Gate change (breaking, decision 5 of
#39):** a non-loopback bind is now allowed iff `--read-only` OR
`--allow-public` OR (`--tls` AND ≥1 configured token) — P29's "tokens alone
justify a public bind" is narrowed, since a token protecting only a
plaintext channel was never the guarantee its wording implied; the refusal
message names `--tls` as the fix. **Deliberate spec deviation (plan-approved,
recorded in ADR-0042):** under TLS, the `--max-connections` busy-shed at the
connection cap closes the socket silently instead of writing a readable
`503` — a readable status would need a TLS handshake on the accept thread,
which would violate ADR-0041's accepts-never-block property; plaintext
connections keep the readable `503` unchanged. Provider choice: ring over
the rustls-default aws-lc-rs (18 crates + cmake vs. 14 crates + C-compiler-
only), aws-lc-rs recorded as the swap-in fallback; pure-Rust providers
(`graviola`, `rustls-rustcrypto`) rejected as immature; ACME rejected
outright (`rustls-acme`'s async stack is the wrong shape for this project's
blocking design). Zero wire-protocol changes; the four `WirePolicy`/
`ServeLimits` bounds from P31 apply unchanged under TLS (set on the inner
`TcpStream`, below the TLS wrap). Proven by `demo/run_tls_demo.sh`: a TLS
round trip carrying a signed chunked blob byte-for-byte, the TOFU
pin/mismatch/strict/pre-pin lifecycle, and the tightened plaintext gate — run
twice, zero residue. **Accepted boundaries:** pin-only trust means no
CA-path validation option yet (deferred, additive for PEM deployments); the
first connection to any host is unverified by construction (the TOFU trade,
same as SSH's first connect); a loopback bind with no tokens configured
stays unauthenticated by design, unchanged from P29. See ADR-0042.

**Phase 33 is built.** Randomized protected-path encryption closes ADR-0014's
convergent equality-confirmation oracle (the audit's remaining protected-path
High, ticket #40) for all **new** content, dual-read for the old. All new
protected content seals under a **fresh random DEK + random nonce**
(`encrypt_path_randomized`, `crates/crypto`), so two seals of the same
plaintext yield different ciphertext ids — the dictionary/equality oracle is
closed from this phase on. **The format tag is a perms-byte flag, not a
blob-layout change:** a new `RANDOMIZED` bit (`0b0000_0010`, always set with
`PROTECTED`) rides the tree entry; the blob is still `nonce(24) ‖ ciphertext`
under the same `PATH_AAD`, decrypted by the unchanged `decrypt_path`, so
dual-read needs ZERO read-path code. The tag lives in the tree entry (not the
blob) so format identification never fetches or decrypts bytes, and so a
format discriminator never perturbs a blob id. **No snapshot-tag bump
(`TAG_SNAPSHOT` stays 4), no `PROTOCOL_VERSION` change (stays 3)** — a pre-P33
store reads byte-for-byte identically, and carry-by-id (the P15/P24 discipline,
preserving the source entry's own perms) rides the bit through merge, replay,
graft, and sparse carry with no new plumbing. **The commit rule is
format-dispatched, not cache-only** (spec §3 table): a prior-tip **convergent**
entry uses today's re-encrypt-and-compare (unchanged → carry as convergent
forever with no cache; edited → seal randomized), a prior-tip **randomized**
entry consults the stat cache, a **new** path seals randomized — a cache-only
rule would have mass-migrated every unchanged protected file on the first
commit after upgrade; format dispatch means unchanged convergent content stays
convergent until an edit or `sc rewrap` touches it. **Unchanged detection is a
per-checkout stat cache** (`crates/repo/src/cache.rs`) keyed by
`.sc/local-key` (32 random bytes, **0600 from the first byte**, lazily minted,
**never committed, never transferred**): entries are `path → (mtime, size,
keyed_tag, blob_id)` with `keyed_tag = BLAKE3-keyed(local_key, plaintext)`.
Commit still needs only **public keys** — decrypt-and-compare is used nowhere.
The cache **does not reintroduce the oracle** because the tag is a PRF output
under a key that never leaves `.sc/`, so the cache file alone leaks nothing;
its worst failure mode is a spurious re-seal (fresh id for unchanged
plaintext), never incorrectness — a corrupt line is treated as absent with a
warning, a missing key is minted, a key that can't be created is a hard error.
**DEVIATION from #30 decision-3's letter (and the spec §3 table): the stat hit
is NEVER trusted alone — the keyed BLAKE3 tag is authoritative in every cache
lookup.** The recorded `(mtime, size)` are advisory; the tag is recomputed and
compared every time. This closes the git racy-stat class (a same-size edit
within mtime granularity, at the recorded mtime, would otherwise be silently
dropped from a commit — pinned by `racy_stat_same_size_same_mtime_still_misses`
and `tag_is_authoritative_for_hits_and_misses`). Rationale: the plaintext is
already in memory at every call site, keyed hashing is ~free against it, and
"never incorrectness" outranks the stat shortcut. **`sc rewrap` performs the
eager upgrade** (no new command, no flag): while re-wrapping each blob's DEK by
wrap presence, it additionally decrypts any still-convergent blob and re-seals
it randomized to `granted_keys() + escrow`, recording the plaintext it already
holds into the main-tree cache (so the next `sc status`/`commit` stays quiet —
rewrap never rematerializes the working tree). Output gains a `re-sealed N
convergent blob(s)` line; a rewrap that upgrades content is **no longer
tree-identical** (accepted cost 4b), while a second rewrap over an
all-randomized tip converges back to policy-only. **A review Critical, fixed:**
two paths sharing ONE convergent blob (pre-P33 dedup of identical plaintext) —
old-id wrap removal is **DEFERRED past the path loop** (removed only when no
kept tree entry still references it); removing it in-loop stripped the shared
entry out from under the second path, leaving it wrap-orphaned at the tip with
no re-run repair. Each shared path mints its own randomized blob, which also
closes the intra-tip oracle between those two paths. **Accepted costs 4a–c all
landed as predicted:** (4a) independent identical edits on two branches now
conflict — both sides editing to even trivially-identical plaintext no longer
id-matches, so the merge needs `--identity` (or P23 `sc conflicts`/`sc
resolve`) even to merge identical content; (4b) rewrap is tree-changing when it
upgrades; (4c) identical plaintext at two paths no longer dedups. **P15/P17
semantic adjustments:** merge/replay's content-divergent re-encryption switches
to the randomized primitive (union/tombstone semantics unchanged; mixed
convergent+randomized trees need no special casing — every path is carried by
id or re-sealed randomized), and `sc rewrap` gains the upgrade above.
**`sc protect <existing-prefix> --to <new>` no longer wraps UNCHANGED content
at the next commit** (review-confirmed real behavior change): unchanged files
carry their prior wrap list verbatim, so a bare re-protect does not grant the
new recipient access to un-re-sealed files. This fails **safe** — it
under-grants, never over-grants — and `sc grant` / `sc rewrap` are the covering
flows (operator guidance: use `sc grant`, not a second `sc protect`, to add a
recipient to already-committed content). **The cache is per-checkout:** the
main tree uses `.sc/protected-cache`; a ws workspace uses `.sc/ws/cache-<i>`
**beside** the checkout dir, never inside it (a file inside `.sc/ws/<i>/` would
be harvested as an untracked working file), removed with the workspace at
teardown; `sc work`'s one-shot agents use ephemeral in-memory caches. Rationale
— without per-workspace caches, untouched protected files in forked workspaces
would have no cache entry, be re-sealed randomized at harvest with a fresh id,
and identical-edit-**conflict** (cost-4a fired spuriously) into a `work-<i>`
fallback instead of a clean auto-merge; per-workspace caches reproduce the base
tree id and preserve P20's clean-auto-merge and crash-recovery `UpToDate`
idempotency. All production cache saves are **best-effort and ordered after ref
moves** — the ref move stays the atomic commit point; a save failure warns,
never errors. **Unlocked follow-on: rotate-for-paths** — ADR-0019 called
per-path DEK rotation security-meaningless under convergent encryption; that
objection **dissolves for randomized content** (a random DEK is independent of
the plaintext), so a `sc protect … rotate` genuine cutover is now coherent —
**recorded, not built.** **Proof splits honestly:** dual-read of genuine
pre-P33 stores is pinned by **library-built convergent-tree fixtures** in the
`rewrap`/`merge`/`replay` unit tests (the current binary can no longer *write*
a convergent blob), while `demo/run_randomized_demo.sh` proves oracle-closure,
quiet history, cost-4a conflicts, and rewrap policy-only on an all-randomized
tip against the current binary (the convergent→randomized rewrap upgrade path
is unit-pinned, not demo-pinned, for the same reason) — run twice, zero
residue. Zero new dependencies (`blake3`/`hex`
were already workspace deps; `scl-repo` now links `blake3` directly for the
cache tag). See ADR-0043.

Remaining follow-ons: operation objects in the CAS, oplog entries for
remote-tracking refs, extending the sparse gate to
`materialize_conflict_state`'s `to_encrypt`/sidecar write loops (see the
P24 boundary note above), the three P27 items named above (transparent
lazy-fetch as a deferred alternative to explicit `sc backfill`, per-case
gap-tolerant merge/rebase/`ws harvest`/`sc work` instead of blanket
refusal, and blob-size/object-count clone filters alongside the
prefix-only filter shipped here), the two remaining P28 items named above
(fd/stdin secret injection as an alternative to env vars, and a
`--max-object-size` operator config knob — randomized protected mode is now
SHIPPED in P33/ADR-0043), the P33 item (**rotate-for-paths** — ADR-0019's
"path DEK rotation is security-meaningless" objection dissolves for randomized
content, so a `sc protect … rotate`-style genuine per-path cutover is now
coherent; recorded, not built), and the P28 final-review follow-ons (a one-line
`validate_branch_name` call in `refs::write_head`/`refs::delete_branch`
for ref-validation class completeness — not exploitable today, since
HEAD's path is fixed and `delete_branch` only takes internally-generated
names; an `SC_PACK_CHUNK` upper-clamp to `MAX_OBJECT_SIZE`, so an
oversized chunk config fails clearly instead of producing frames the
receiver's cap silently rejects; `Repo::worktree_paths` doing a
paths-only walk instead of loading every file's full bytes; and
extracting a shared `path_under_prefix(path, prefix)` helper so
`run_protect`'s `/`-boundary filter and `protect.rs::matching_prefix`
stop duplicating the same rule), and the P30 items — `--transcript auto`
probing, `sc transcript drop` + a resurrection tombstone, transcript
access lifecycle (rewrap/grant/revoke), a `--no-transcripts` transfer
knob, `sc export --transcripts=entire`, per-turn live checkpointing, and
the P30 final-review follow-ons (threading `--transcript`/`--sign`
through `Repo::ws_harvest` itself instead of the current CLI-side
post-harvest seam; `sc transcript list` with no `<ref>` walking the full
DAG rather than only the first-parent mainline; a
`transcripts_ride_ssh_transport` wire-harness test twin; and the
now-stale `SignatureObj.snapshot` doc comment, which still describes the
field as always a snapshot id though signing a transcript stores a
transcript id there instead), and the P32 items — CA-path validation as an
additive trust option alongside pin-only for PEM-provisioned deployments,
opt-in SNI/certificate-name validation (v1 is pin-only and ignores names),
pin-management UX (`sc tls` list/remove entries in
`~/.config/sc/known_hosts` — today only `sc serve fingerprint` prints and
first-connect/`SC_HTTPS_FINGERPRINT` write), and TLS session-resumption
knobs (not evaluated in this phase; a later throughput pass if repeated
short-lived connections to the same host prove handshake cost material).

