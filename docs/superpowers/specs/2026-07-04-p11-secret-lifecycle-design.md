# P11 — Secret/permission lifecycle (rotation + escrow): design

- **Status:** Approved (brainstorm); pending implementation plan
- **Date:** 2026-07-04
- **Phase:** 11
- **Refines:** ADR-0019 (new; firm to Accepted at build time)
- **Builds on:** ADR-0008/0009/0010 (committed secrets, envelope encryption,
  key management), ADR-0014 / P7 (per-file permissions / encrypted paths)
- **Records the now-built decision deferred by:** ADR-0008 ("true revocation of
  an already-disclosed secret still requires rotating the value"), ADR-0009
  ("Recovery/rotation policy must be defined… a break-glass recipient key held
  in escrow is the recommended mitigation, documented when the feature is
  built"), ADR-0014 (same rotation caveat for protected paths)

## Goal

Give committed secrets a lifecycle. Today `sc secret revoke` is **metadata-only**
(`crypto/src/envelope.rs:110` — it drops a recipient's wrapped key but leaves the
value and DEK unchanged), so a revoked party who kept their old DEK can still
decrypt the value. The ADRs acknowledge this and defer the fix. P11 builds the
two capabilities that close it:

1. **Rotation** — re-seal a secret's value under a fresh DEK, cutting off future
   reads through the current registry by anyone holding the old DEK.
2. **Break-glass / escrow** — an escrow recipient key auto-included at seal and
   protect time, so an organization can always recover even if every individual
   authorized key is lost.

**Bulk re-wrap is out of scope** this phase (retrofit is per-secret; noted as a
follow-on).

## Decisions (locked in brainstorm)

### 1. Rotation is a compose of existing crypto primitives — no new primitive

Rotation is `seal` (new value) or `open` + `seal` (same value). The work lives in
`repo` + `cli`; **`crates/crypto` is unchanged**, so its quarantine holds by
construction. A dedicated `reseal` crypto primitive was rejected as YAGNI.

### 2. Rotation is for secrets only; protected-path value-rotation is scoped OUT

P7 protected paths use **convergent** encryption: the DEK is
`HKDF(BLAKE3(plaintext))` (`crypto/src/envelope.rs:126`). A recipient who checked
out a protected file already holds the plaintext and can **re-derive the key**, so
"rotating a path's DEK" is either dedup-breaking or security-meaningless — and new
content already yields a new key naturally. Therefore rotation applies to secrets
(random DEK, clean to re-seal); the meaningful path lifecycle op is recipient
re-wrap (existing grant/revoke), not value rotation. Escrow still applies to paths
(§4) — that is recipient-set management, not rotation.

### 3. `secret rotate` command shape

`sc secret rotate <name> [--value <new>] [--to <names>] [--identity <key>]`
produces a new snapshot pointing the registry at a freshly-sealed `Secret` (fresh
random DEK + nonce):

- **New value** (`--value` given): seal the new plaintext. No decryption, so no
  `--identity` required.
- **Same value, new DEK** (`--value` omitted): recover the current plaintext with
  `--identity` (must be a current recipient) via `open`, then re-seal it under a
  fresh DEK.
- **Recipient set:** defaults to the secret's *current* recipients, resolved by
  matching each stored `recipient_id` back to a pubkey in `.sc/recipients.toml`
  (reverse lookup: for each `[recipients]` pubkey, compute its `recipient_id` and
  match). `--to <names>` overrides. In same-set mode, any current `recipient_id`
  not resolvable from `recipients.toml` is a hard error that lists the unresolved
  ids (we cannot re-wrap a pubkey we do not have).
- Escrow (§4) is appended to the recipient set before sealing (deduped).

### 4. Break-glass / escrow recipient

An escrow recipient pubkey is **auto-appended** to the recipient set whenever a
secret is sealed or a path is protected.

- **Storage:** `.sc/recipients.toml` gains an `[escrow]` section holding one
  escrow pubkey (the file already maps names→pubkeys and is the recipient source
  of truth). One escrow key for the MVP; multiple is a later extension.
- **Managed via:** `sc escrow set <pubkey-or-name>` and `sc escrow show`.
- **Auto-append points:** `secret add`, `secret rotate`, and `protect` append the
  escrow pubkey before sealing/wrapping (deduped, so passing it explicitly is
  harmless). `grant`/`revoke` are unchanged. Escrow is not revocable through the
  normal recipient path (revoking it defeats its purpose); removing escrow means
  clearing the config and rotating.
- **Forward-only:** existing secrets/paths do not retroactively gain escrow; they
  acquire it the next time they are rotated (secrets) or re-wrapped (paths).
  Retrofit is per-secret this phase (bulk re-wrap deferred).
- **Covers protected paths too:** `protect` appends escrow to each file's
  wrapped-DEK recipient set, so the escrow holder can decrypt protected files —
  one-key recovery across both secrets and per-file permissions.

### 5. `revoke` stays metadata-only

`sc secret revoke` and `sc revoke` (path) are unchanged in behavior. `secret
revoke` gains a printed hint: "run `sc secret rotate` for a cryptographic
cutover." This keeps existing behavior backward-compatible and composable
(revoke, then rotate).

## Honest limitations (stated in ADR-0019, `--help`, and demo output)

- **Rotation ≠ erasure.** A content-addressed history means re-sealing creates a
  *new* `Secret` object and repoints the registry, but the *old* ciphertext
  object stays reachable from every historical snapshot and remains decryptable by
  anyone who kept the old DEK. `sc gc` will not reclaim it (it is referenced by
  history). Rotation cuts off *future* reads through the current registry; real
  security is realized **together with rotating the underlying external
  credential** (the actual DB password changes). This is the same framing as the
  existing git-export plaintext-history caveat.
- **Escrow is policy, not enforcement.** Auto-append protects against key loss
  among cooperating users. It cannot bind an adversarial committer who uses the
  raw API or omits the escrow config. Stated plainly in `escrow show` output and
  the ADR.

## Crate boundaries & where the code lives

Dependency direction (`cli → repo → {vfs, gitio, crypto} → core`) is unchanged.

- **`crates/crypto`** — *unchanged.* Rotation reuses `seal`/`seal_with_rng`/
  `open`; escrow adds no cryptography.
- **`crates/repo/src/secrets.rs`** — gains
  `secret_rotate(&self, name: &str, new_value: Option<&[u8]>, recipients: &[PublicKey], identity: Option<&SecretKey>) -> Result<ObjectId>`.
  It resolves the plaintext (from `new_value`, or by `open`-ing the current secret
  with `identity`), seals fresh, updates the registry, and commits a new snapshot
  — mirroring the existing `secret_add`/`secret_grant` snapshot-commit pattern.
  The `recipients` slice arrives already including escrow (appended by `cli`), so
  `repo` has one seal path.
- **`crates/repo`** — no `recipients.toml` parsing (stays in `cli`). `repo`
  methods receive resolved `PublicKey`s, exactly as `protect`/`secret_add` do
  today, so `repo` never learns the recipients-file format.
- **`crates/cli`** — new `sc secret rotate` and `sc escrow set`/`sc escrow show`
  subcommands; owns `recipients.toml` including the new `[escrow]` section; does
  the `recipient_id → pubkey` reverse lookup for rotation's default recipient set;
  appends the escrow pubkey to the recipients slice for `secret add`, `secret
  rotate`, and `protect`; prints the caveats and the revoke→rotate hint.

## Data flow

**`secret rotate <name> --value NEW`:** cli resolves recipients (current set via
reverse lookup, or `--to`) + appends escrow → calls `repo.secret_rotate(name,
Some(NEW), recipients, None)` → repo seals NEW under a fresh DEK for the set,
puts the `Secret`, repoints the registry, commits a snapshot.

**`secret rotate <name>` (same value):** cli resolves recipients + escrow, loads
`--identity` → `repo.secret_rotate(name, None, recipients, Some(id))` → repo
`open`s the current secret with `id`, re-seals the recovered plaintext under a
fresh DEK, repoints, commits.

**`escrow set <key>`:** cli writes the `[escrow]` pubkey into `recipients.toml`.
Subsequent `secret add`/`rotate`/`protect` include it automatically.

## Testing & demo

**Unit / integration** (in-crate `#[cfg(test)]`, temp dirs cleaned up):

- *repo `secret_rotate`:* new-value rotation seals a fresh DEK and the recipient
  set reads the new value; same-value rotation (via `identity`) recovers and
  re-seals — assert the stored object id changed **and** the pre-rotation DEK no
  longer `open`s the new object; default rotation preserves the recipient set;
  `--to` changes it; same-set rotation errors when a current `recipient_id` is
  absent from `recipients.toml`.
- *True-cutover property (headline test):* seal a value for Alice+Bob → confirm
  Bob decrypts → `revoke` Bob (assert Bob's wrapped key is gone from the new
  object, value unchanged, and — the point of metadata-only revoke — Bob's
  retained DEK still opens the *unrotated* object) → `rotate` → assert the rotated
  object's DEK differs and Bob, even with the old DEK bytes, cannot `open` the
  rotated object. Encodes the exact revoke-vs-rotate distinction the phase fixes.
- *Escrow:* with `[escrow]` set, `secret add` and `protect` both include the
  escrow recipient (the escrow identity decrypts); rotation re-includes escrow;
  explicit escrow is deduped (no double wrap); `escrow show` prints the
  non-guarantee.
- *cli:* `sc secret rotate` end-to-end across a reopen; `sc escrow set`/`show`;
  the unresolved-recipient error path.

**End-to-end demo** — `demo/run_lifecycle_demo.sh` in the existing style: keygen
an escrow key + two user keys → `sc escrow set` → `sc secret add` (show escrow
auto-included via `secret list` recipient count) → `sc secret rotate --value`
(show it still runs) → the cutover narrative (revoke a user, rotate, show the
escrow key still recovers) → echo the honest caveat. Independent, scriptable.

## Docs to update at build time

- New **ADR-0019** (secret/permission lifecycle: rotation + escrow),
  Proposed→Accepted with refinements; cross-references (does not mutate)
  ADR-0008/0009/0014's rotation-deferred notes. Add to the ADR index (Phase 11).
- **ROADMAP.md** P11 entry (Done + table) and the deferred list (drop break-glass
  escrow; note bulk re-wrap and multi-escrow as sub-follow-ons; secret value
  rotation now built).
- **CLAUDE.md** command list (`secret rotate`, `escrow set/show`, demo), a "Phase
  11 is built" note, and update "Remaining follow-ons" to drop break-glass escrow
  (leaving network transport).

## Non-goals (this phase)

- **Bulk re-wrap** of all secrets + protected prefixes on an org-wide recipient
  change (per-secret retrofit only).
- **Multiple escrow keys** / escrow key rotation (single key this phase).
- **Protected-path value rotation** (security-meaningless under convergent
  encryption — §2).
- **Making `revoke` re-seal** (revoke stays metadata-only; rotate is the cutover).
- **Reclaiming old ciphertext from history** (content-addressed history keeps it;
  not erasure).
