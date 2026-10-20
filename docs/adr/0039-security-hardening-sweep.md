# ADR-0039: Security hardening sweep

- **Status:** Accepted
- **Date:** 2026-07-09
- **Phase:** 28
- **Builds on:** ADR-0021 (durability/concurrency hardening — the P21 sweep precedent), ADR-0022 (ssh wire protocol), ADR-0015 (packfiles), ADR-0014 (protected paths), ADR-0008/0009 (secrets)

## Context

A 2026-07-09 security audit surfaced six findings; each was dispositioned via the
wayfinder map (`docs/superpowers/specs/2026-07-09-security-hardening-design.md`,
tracker issues #1–#9). Four are small, independent, fix-now items with settled
designs; they group into one P21-shaped hardening sweep, security-only with no new
feature axis. The larger fifth (sc+http access control) is deferred to its own phase
(ADR-0040, P29). This ADR covers only the sweep.

## Decision

Build the four fix-now decisions from the security-hardening spec verbatim — no new
design; this ADR points at that spec for detail:

1. **Remote UpdateRef ref-name validation (audit High, the one genuine bug).** Apply
   the strict `validate_branch_name` at the lowest ref-write boundary
   (`refs::write_branch_tip` + `read_branch_tip`) — one choke point for every writer
   (CLI, wire `UpdateRef`, undo, ws), protecting both the `refs/heads/` filesystem path
   and the space-delimited oplog format. Also upgrade `write_remote_tip`'s
   `is_unsafe_ref_component` to reject whitespace/control (a hostile-git-remote gap
   found while resolving). Both ref-write paths hardened.
2. **DoS caps (audit High).** A single `MAX_OBJECT_SIZE` constant (~256 MiB) caps the
   wire frame size (`read_frame_inner`), the pack-record compressed length, and the
   zstd decompressed output (decompression-bomb guard); chunk frames stay bounded by
   the existing `CHUNK_SIZE`. The four object-decode `Vec::with_capacity(n)` sites
   (tree entries, snapshot parents, secrets, signature wrapped-keys) switch to the
   existing `Reader::count()` guard.
3. **Protected-path equality nudge (audit Medium — accept + surface).** Accept the
   convergent-encryption caveat (deliberate, ADR-0014); add a pattern-aware `sc protect`
   stderr nudge steering low-entropy secret basenames (`.env`/`*.key`/creds…) to
   `sc secret`, plus stronger help/docs. Randomized protected mode deferred.
4. **Secret env-var confidentiality (audit Medium — accept + docs + zeroize).** Tighten
   threat-model wording to "authorized local process context, NOT strong isolation";
   wrap the intermediate decrypted plaintext buffer in `crypto::Zeroizing` to zero the
   parent's copy on drop. fd/stdin injection deferred.

## Consequences

- The two concrete-bug Highs (ref-traversal, DoS) are closed; the two Mediums are
  accepted-and-surfaced. No new user-facing feature axis; no new dependency.
- Demoable outcome is P21-shaped: each audit repro becomes a pinned regression test,
  and every existing demo stays green — the sweep ships no new demo script.
- sc+http access control (auth) is explicitly deferred to P29 (ADR-0040).

## Alternatives considered

- **One combined phase with the sc+http auth.** Rejected: mixes four mechanical fixes
  with a substantial auth feature (CLI + config + wire-opening parse) — heterogeneous,
  plan-heavy, weaker review boundaries.
- **Auth phase first.** Rejected: the auth is the larger, higher-risk unit; the sweep
  first closes the concrete bugs sooner and de-risks.

## Refinements discovered during the build

The four decisions above landed as designed; the build surfaced exact fix sites and
one finding worth recording precisely.

**Decision 1 is two validators, kept distinct on purpose.** `refs::write_branch_tip`
and `refs::read_branch_tip` (`crates/repo/src/refs.rs`) both now call the existing
strict `validate_branch_name` (rejects empty, `.`/`..`, leading-dot, `/`, `\`,
whitespace, control) — the single lowest-boundary choke point every local-branch
write reaches: the CLI, the wire `UpdateRef` arm, `sc undo`, and `sc ws`. Separately,
`is_unsafe_ref_component` — the `/`-permitting validator guarding remote-tracking
`write_remote_tip`, which must allow `origin/main`-shaped components that
`validate_branch_name` would reject — was upgraded to also reject whitespace/control,
closing an oplog-corruption gap via a hostile git remote's branch name. Two
validators stay two validators; neither subsumes the other. 4 pinned regression
tests (`refs.rs`).

**Decision 2 anchors on one constant with a decode-WITH-LIMIT zstd mechanism.**
`MAX_OBJECT_SIZE = 256 * 1024 * 1024` (`crates/core/src/lib.rs`) is the sole anchor
for every untrusted-length guard: `wire::read_frame_inner`'s frame length, before
`vec![0u8; len]`; `pack::parse_pack_reader`'s compressed record length, before alloc;
and the zstd DECOMPRESSED output, bounded by streaming through
`zstd::stream::read::Decoder` wrapped in `.take(MAX_OBJECT_SIZE as u64 + 1)`
(`crates/core/src/pack.rs`) — a decode-WITH-LIMIT, not decode-then-check, so a
decompression bomb never fully materializes before rejection. The four
object-decode count sites (TAG_TREE entries, TAG_SNAPSHOT parents, TAG_SNAPSHOT
secrets, TAG_SECRET wrapped_keys) switched from a raw `r.u32()` to the existing
`Reader::count()` guard, which already rejects a count exceeding remaining input
bytes. Scope is deliberately the untrusted-peer path only (`parse_pack_reader`);
`read_object_at`'s local already-verified on-disk pack is untouched. The DoS
regression pins span three files, not just `pack.rs`: `pack_record_over_cap_rejected`
and `zstd_bomb_rejected` (`pack.rs`), `object_decode_fabricated_counts_rejected`
(`object.rs`), and — closed in the P28 final review, the client-side `ListRefs`
count gap `Cur::count()`/`decode_refs_body` missed on the wire path —
`frame_over_cap_rejected` and `decode_refs_body_rejects_fabricated_count`
(`wire.rs`). No new dependency — `zstd` was already present.

**Final-review addendum: the cap is transfer-path only, not a local-commit
limit.** `MAX_OBJECT_SIZE` is enforced where untrusted bytes are received
(`parse_pack_reader`, `wire::read_frame_inner`), not at local `commit`/
`Store::put`. A locally-committed blob larger than 256 MiB therefore commits
fine but then fails at every subsequent sync (`push`/`fetch`/`clone`) once it
hits a receiver's cap. Accepted MVP boundary — committable but not
transferable — and part of the case for the deferred `--max-object-size`
operator knob (see ROADMAP).

**Decision 3's heuristic is filename-only, deliberately distinct from the P5
content scanner.** `looks_like_low_entropy_secret(basename)`
(`crates/cli/src/main.rs`) matches `.env`/`.env.*`/`*.pem`/`*.key`/`id_*`/
`*credentials*`/`*.p12` against a working-tree path's basename only — it does not
read file content or run the P5 entropy/pattern scanner, and a `/`-boundary match on
the governed prefix keeps a sibling like `secret-evil/x` from matching a `sc protect
secret` prefix. `sc protect <prefix>` prints one stderr warning citing ADR-0014 and
proceeds regardless — exit code and result unchanged. Accepted boundary, not a bug:
convergent encryption stays equality-confirmable by design; randomized protected
mode stays deferred.

**Decision 4 turned out to be docs + a compile-time pin, not new zeroize work.**
`scl_crypto::open` already returns `Zeroizing<Vec<u8>>` — the decrypted plaintext
was already zeroized on drop before this phase touched it. `Repo::secret_env`
(`crates/repo/src/secrets.rs`) types its intermediate binding explicitly as
`Zeroizing<Vec<u8>>` and a dedicated test (`secret_env_plaintext_is_zeroizing`)
pins `scl_crypto::open`'s signature at compile time, so a future change that
stopped returning `Zeroizing` fails to compile rather than silently regressing.
The real work was tightening the threat-model wording (ADR-0008, CLAUDE.md, `sc
run --help`) to "authorized LOCAL PROCESS context, NOT strong isolation" — the
unavoidable `OsString` hand-off into the child's environment is observable by
same-user processes, crash dumps, and shell wrappers, and no amount of zeroizing
the parent's buffer changes that. Accepted boundary: the child-env copy is
fundamental and un-zeroizable; fd/stdin injection stays deferred. 1 pinned
regression test.

## Addendum (#213): the object cap is operator-configurable

`MAX_OBJECT_SIZE` was a compile-time constant. It is now a process-wide
setting read through one accessor, `scl_core::max_object_size()`, with a
default of 256 MiB. Decisions:

1. **Lower or raise, inside a compile-time range.** Floor 2 MiB
   (`MIN_MAX_OBJECT_SIZE`; a default peer's pack chunk frame is 1 MiB plus a
   tag byte, which a 1 MiB cap would refuse), ceiling 1 GiB (`MAX_MAX_OBJECT_SIZE`). A value
   outside the range, or one that does not parse, aborts startup with a clear
   error. It is never clamped. The ceiling bounds what a hostile peer can
   make a receiver commit to for any one object whatever the operator sets.
2. **Server flag and client env, no negotiation.** `sc serve
   --max-object-size <bytes|KiB|MiB|GiB>` and, for every `sc` process,
   `SC_MAX_OBJECT_SIZE` (same parse, same bounds). The flag wins over the
   env. An empty `SC_MAX_OBJECT_SIZE` counts as unset. The setting is fixed
   by whichever comes first, the startup `set_max_object_size` or the first
   `max_object_size()` read; a later, different value is an error. There is no handshake field and no
   `PROTOCOL_VERSION` bump: the operator must make each receiver's cap
   admit the objects it will receive, because an object larger than the
   receiver's cap fails at the receiver (only the receiving side's cap applies
   to incoming frames and records). The failure is loud and typed, never silent truncation, and
   the frame and pack-record errors name `SC_MAX_OBJECT_SIZE` /
   `--max-object-size` as the thing to raise on the refusing side.
3. **Every guard reads the accessor.** Frame length (`wire::read_frame_max`,
   limit `cap + FRAME_OVERHEAD`, 64 bytes, so an object of exactly the cap fits
   inside its `PutObject`/`GetObject` envelope; `wire::check_object_len` then
   checks the object body against the cap exactly);
   pack record compressed length and decompressed output
   (`pack::parse_pack_reader_max`, `read_object_at_bounded`); bucket pack
   bodies (`bucket_transport::object_bytes`); server-side servable-size check
   (`check_servable_size`, against the largest configurable cap, not the
   server's own: the cap is receiver-only, so a server with a lower cap still
   serves a larger local object by id, as `GetPack` does); the `SC_PACK_CHUNK` clamp (`cap - 1`, a chunk
   frame carries a tag byte); the `--max-pack-size` floor
   (`validate_max_pack_size`). Two exceptions are deliberately fixed, not derived from the cap. Bucket
   WAL metadata (manifest, log entry, idx) stays capped at the default
   256 MiB: it is metadata, not an object, and a lowered cap would make a
   bucket with a large pack index (48 bytes per entry) unreadable. That check
   runs after the bucket GET has buffered the value, so it bounds decode work
   rather than the download, the one place a length is checked after
   allocation. The by-id reply ceiling (server, `2 x` the maximum configurable
   cap = 2 GiB, still `min(--max-pack-size, ceiling)`) and the client's by-id
   read cap (twice that) are constants: they bound a disk spool, not RAM, and
   if they followed the local cap, peers with different caps would disagree
   about whether a by-id batch containing no large object fits. Each guard takes the cap
   as a parameter below the public entry point so tests can drive a lowered
   and a raised cap without touching the process-global.
4. **Allocation follows bytes received.** The length check still runs before
   any allocation, but the frame body and pack record payload are now read
   through `scl_core::read_limited` / `read_exact_vec`, which grow the buffer by
   `reserve_exact` steps as bytes arrive instead of pre-allocating the
   claimed length. Steps are geometric up to 8 MiB, then `max(8 MiB, filled/8)`,
   so capacity never exceeds the bytes received by more than the larger of
   8 MiB and 12.5%, and total copying stays linear; the zstd decompressed
   output uses the same reader (still bounded at `cap + 1` to detect overflow).
   With the ceiling at 1 GiB, a four-byte header or a decompression bomb no
   longer buys a gigabyte-sized allocation. This closes the "frame header can
   allocate up to the cap" item in THREAT-MODEL.md.

The resident-blob budget of a repo or transport store was a fixed 512 MiB; a
raised cap would have admitted frames the store then refused with
`BudgetExceeded`. The default is now `max(512 MiB, 2 x cap)`
(`repo::default_budget`), unchanged at the default cap. It applies to
`Repo::open`/`init` and to `LocalTransport` (so also to a served connection).
The env var therefore changes the default budget of every local command that
opens a repo, not just transfers. An explicit budget (`sc work --budget-mb`,
`Repo::open_with_budget`) overrides the default and can be smaller than an
object.

Raising the cap raises the memory a peer can make a receiver hold per
connection, in two parts: transient pack decode memory (compressed +
decompressed while decompressing, then decompressed + decoded while decoding,
the compressed copy being released in between: peak about 2 x cap; a
single-object `PutObject` or `GetObject` is also about 2 x cap, the request
frame being moved into the object body rather than copied) plus that
connection's own store budget (each served connection opens its own store,
`max(512 MiB, 2 x cap)`). At the default that is about 0.5 GiB + 0.5 GiB; at
the 1 GiB ceiling about 2 GiB + 2 GiB, per connection, times
`--max-connections` (THREAT-MODEL.md).

For `ssh://` remotes the client builds the remote `sc serve --stdio` command
itself and ssh does not forward the environment, so the server end of an ssh
remote gets a non-default cap only from the server's own environment (a
wrapper script, `sshd` `SetEnv`, or a forced command passing
`--max-object-size`).

Unchanged: the cap is still a transfer-path guard, not a local-commit limit,
so lowering it can leave a repository holding committed objects it cannot
push; `read_object_at` (the trusted on-disk path) stays uncapped. The
desktop app does not read the env var; it does no transfers.
