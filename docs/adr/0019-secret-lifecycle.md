# ADR-0019: Secret/permission lifecycle (rotation + escrow)

- **Status:** Accepted
- **Date:** 2026-07-04
- **Phase:** 11

## Context

`sc secret revoke` (ADR-0008/0009) is **metadata-only**: it drops a recipient's
wrapped key from the `Secret` object but leaves the value and DEK unchanged.
A revoked party who kept their old DEK can still decrypt the value — the ADRs
acknowledged this and deferred the fix: ADR-0008 noted "true revocation of an
already-disclosed secret still requires rotating the value," and ADR-0009
recommended "a break-glass recipient key held in escrow… documented when the
feature is built." ADR-0014 recorded the same rotation caveat for per-file
protected paths.

This ADR records the decisions made to close that gap: a true cryptographic
cutover (rotation) and an organizational recovery mechanism (escrow), both
scoped to what is needed now, deferring bulk operations and multi-key escrow.

## Decision

### Rotation is a compose of `seal`/`open` — no new crypto primitive

Rotation re-seals a secret's value under a fresh random DEK. It is implemented
entirely as `seal` (new value) or `open` then `seal` (same value, recovered
via `--identity`) — both already-shipped primitives from `crates/crypto`. A
dedicated `reseal` primitive was rejected as unnecessary: `crates/crypto`
remains unchanged, so its quarantine (ADR-0004) holds by construction and no
new cryptography needed review.

`repo::secret_rotate(name, new_value: Option<&[u8]>, recipients: &[PublicKey],
identity: Option<&SecretKey>)` resolves the plaintext (from `new_value`, or by
opening the current secret with `identity`), seals it fresh, repoints the
registry, and commits a new snapshot — the same commit-producing shape as
`secret_add`/`secret_grant`. `repo` receives already-resolved `PublicKey`s; it
never parses `recipients.toml`.

`sc secret rotate <name> [--value <new>] [--to <names>] [--identity <key>]`:
recipients default to the secret's *current* set, found by reverse lookup
(compute each `recipients.toml` pubkey's `recipient_id` and match against the
secret's stored ids); `--to` overrides. Same-set rotation hard-errors, listing
unresolved ids, when a current recipient can't be matched back to a pubkey —
rotation cannot re-wrap a key it doesn't have.

### Rotation is secrets-only; protected-path value rotation is out of scope

Per-file permissions (ADR-0014) use **convergent** encryption: the DEK is
derived as `HKDF(BLAKE3(plaintext))`. Anyone who has checked out a protected
file already holds the plaintext and can re-derive its key, so "rotating a
path's DEK" is either dedup-breaking (if forced to a random DEK, breaking the
scheme's whole point) or security-meaningless (new content already yields a
new key naturally, and old content's key is trivially re-derivable by anyone
who saw it). Rotation therefore applies only to secrets, whose DEK is random
and cleanly re-sealable. The meaningful lifecycle operation for paths is
recipient re-wrap — the existing `grant`/`revoke` — not value rotation.
Escrow (below) still applies to paths: that is recipient-set management, not
rotation, and composes cleanly with convergent encryption.

### `revoke` stays metadata-only

`sc secret revoke` and `sc revoke` (path) behavior is unchanged — dropping a
recipient's wrapped key, nothing more. `secret revoke` now prints a hint:
"run `sc secret rotate` for a cryptographic cutover." This keeps `revoke`
backward-compatible and composable: revoke removes access going forward
through normal channels, rotate is the operation that actually invalidates
the value for anyone who kept a copy of the old DEK.

### Break-glass escrow: single key, auto-appended, forward-only

`.sc/recipients.toml` gains an `[escrow]` section holding one pubkey — the
file is already the recipient source of truth, so this avoids a second config
surface. Managed via `sc escrow set <pubkey-or-name>` and `sc escrow show`.

- **Auto-append points:** `secret add`, `secret rotate`, and `protect` append
  the escrow pubkey to the recipient set before sealing/wrapping, deduped by
  key bytes so passing it explicitly is harmless. `grant`/`revoke` are
  unchanged — escrow is not managed through the normal recipient path, since
  revoking it would defeat its purpose. Removing escrow means clearing the
  config and rotating/re-wrapping affected secrets/paths.
- **Forward-only:** existing secrets and protected paths do not retroactively
  gain escrow coverage; they acquire it the next time they're rotated
  (secrets) or re-wrapped (paths). Retrofitting the whole repo at once (bulk
  re-wrap) is out of scope this phase.
- **One key, this phase.** Multiple escrow keys / escrow key rotation is a
  later extension; `[escrow]` holds a single pubkey.
- **Covers protected paths too**, since `protect` appends escrow to each
  file's wrapped-DEK recipient set — one recovery key across both secrets and
  per-file permissions.

### Escrow is policy, not enforcement

Auto-append protects cooperating users against losing every individual key.
It cannot bind an adversarial committer who calls the underlying `repo` API
directly or omits the escrow config — there is no server-side gate forcing
escrow inclusion. `sc escrow show` states this plainly, as does this ADR.

## Consequences

- Committed secrets now have a genuine cryptographic cutover
  (`sc secret rotate`), closing the gap ADR-0008/0009 deferred: after
  rotation, a party who retains only the *old* DEK cannot open the *new*
  registry object, even though they were never explicitly revoked from it.
- Organizations get a single-key recovery path (`sc escrow set`) that composes
  automatically with `secret add`/`rotate`/`protect`, addressing ADR-0009's
  "recovery/rotation policy must be defined" note without inventing new
  cryptography.
- **Rotation ≠ erasure.** Because history is content-addressed, re-sealing
  produces a *new* `Secret` object and repoints the registry, but the *old*
  ciphertext object stays reachable from every historical snapshot that
  referenced it and remains decryptable by anyone who kept the old DEK.
  `sc gc` will not reclaim it — it is still referenced by history. Rotation
  cuts off *future* reads through the *current* registry; real security is
  only realized together with rotating the underlying external credential
  (e.g. actually changing the database password). This is the same framing as
  the plaintext-history caveat already documented for `sc export`
  (ADR-0016/0018).
- `crates/crypto` is untouched by this phase; the RustCrypto quarantine
  (ADR-0004) holds without review.
- `crates/repo` continues to receive resolved `PublicKey`s and never parses
  `recipients.toml`; `crates/cli` owns the `[escrow]` section, the reverse
  recipient lookup, and the escrow-append call sites.
- Remaining follow-ons, tracked in `ROADMAP.md`: bulk re-wrap (retrofitting
  escrow/recipient changes across all secrets and protected prefixes at once)
  and multiple escrow keys.

This ADR **records** the rotation/escrow decisions that ADR-0008, ADR-0009,
and ADR-0014 explicitly deferred; it does not modify or supersede those
records, which remain immutable as originally accepted.

## Alternatives considered

- **A dedicated `reseal` crypto primitive.** Rejected — rotation is fully
  expressible as `seal` or `open`+`seal` with a fresh DEK; a new primitive
  would duplicate existing logic and needlessly widen `crates/crypto`'s
  reviewed surface for no capability gain.
- **Rotating protected-path DEKs.** Rejected — convergent encryption (§
  Decision) makes a path's DEK either re-derivable by anyone with the
  plaintext or, if forced random, incompatible with the dedup property the
  scheme exists for. Recipient re-wrap (existing grant/revoke) is the correct
  lifecycle operation for paths.
- **Making `revoke` re-seal automatically.** Rejected — conflates two
  distinct operations (removing a recipient vs. invalidating a value) and
  would silently make every revoke expensive (a full re-seal + commit) even
  when the caller only wants recipient-set bookkeeping. Keeping them separate
  and composable (`revoke` then `rotate`) is simpler and matches the existing
  `grant`/`revoke` mental model.
- **Multiple escrow keys / an escrow key registry.** Rejected for this phase
  as unnecessary complexity — a single organizational recovery key satisfies
  the break-glass use case ADR-0009 called for. Recorded as a follow-on.
- **Bulk re-wrap of all secrets/paths when escrow or recipients change.**
  Rejected for this phase — retrofit is per-secret (rotate) or per-path
  (re-wrap) only; an org-wide bulk operation is a larger, separable feature
  recorded as a follow-on rather than bundled into this phase's scope.
- **Enforcing escrow inclusion server-side (rejecting seals that omit it).**
  Rejected — there is no server/authority boundary in this model to enforce
  against; `repo` trusts the recipient set `cli` passes it, the same trust
  boundary every other secret operation already has. Escrow is documented as
  policy, not a security boundary.
