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
