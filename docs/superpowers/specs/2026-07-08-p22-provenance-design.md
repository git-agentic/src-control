# P22 — Signed commits & provenance: design

**Date:** 2026-07-08
**Status:** Approved
**ADR:** 0032 (Proposed → Accepted when built)
**Horizon:** `2026-07-08-roadmap-horizon-p21-p24-design.md`

## Problem

Content addressing detects object tampering but not history REWRITING: an
attacker who rebuilds internally-consistent objects and re-points a ref
produces valid ids. Nothing binds a snapshot to the identity that created
it. Signatures are the last unbuilt governance pillar.

## Decided design

### Crypto & identity (crates/crypto only)

- `ed25519-dalek` joins the quarantined crypto crate — the one justified
  new dependency of this horizon.
- **Identity v2 (user-decided: unified):** one identity file whose seed
  derives BOTH the X25519 encryption key and an Ed25519 signing key.
  `sc keygen` emits v2. v1 files keep working for encryption; a signing
  key cannot be derived from an X25519 key, so **v1 holders re-key to
  sign** (their encryption standing is unaffected; documented).
- `recipients.toml` grows `[signing]` (name → `scl-sig-…` public key) and
  `[signers] trusted = [names…]` — the trust policy, alongside escrow.

### The signature object

New CAS object kind `TAG_SIGNATURE = 5`:

```
Signature { snapshot: ObjectId, signer: [u8; 32] /* ed25519 pk */, sig: [u8; 64] }
```

The signed message is the domain-separated snapshot id:
`"sc-snapshot-sig-v1" || id` — under BLAKE3 collision resistance this
attests the full canonical encoding. Content addressing gives dedup
(identical signatures collapse) and integrity for free. Snapshot ids are
untouched; retroactive signing of any historical commit is natural.

### Storage, reachability, transfer

- Signature objects are referenced by nothing, so `.sc/signatures` (a
  local index: snapshot id → signature object ids, plain lines, atomic
  writes) provides lookup and gc rooting.
- gc: index entries whose SNAPSHOT is unreachable are dropped during gc,
  un-rooting their signature objects for pruning — signatures never keep
  dead history alive.
- Transfer needs ZERO wire-protocol changes: push/fetch/clone senders
  include indexed signatures for the snapshots being transferred in the
  existing pack; receivers scan received object ids (`put_pack` already
  returns them) for TAG_SIGNATURE and append to their index. Works
  identically over local paths and the P12 ssh transport.
- sc↔git boundary: signatures are dropped with a warning count
  (`signatures_dropped`, like `secrets_dropped`).

### Commands

- `sc commit --sign` / `sc amend --sign` — sign the new tip with the
  identity from the usual resolution chain (flag, `SC_IDENTITY`,
  default path); errors clearly on a v1 (signing-incapable) identity.
- `sc sign <ref> [--identity <key>]` — retroactively sign a ref's tip.
  [As shipped (P22): `<ref>` resolves via `refs::resolve_tip` — a branch
  or remote-tracking name, not an arbitrary historical commit id. Signing
  a mid-history commit means checking it out (or a branch pointing at it)
  first; a resolve-a-bare-commit-id surface is a deferred follow-on.]
  This is also the MVP answer for merge/pick/rebase results: re-sign
  after, instead of threading `--sign` through every operation.
- `sc log` — per-commit marker: `signed: <name> ✓` (trusted),
  `signed: <hex-prefix> ?` (valid signature, key not in [signers]),
  nothing when unsigned. Invalid signatures (bad sig bytes for the id)
  render `signature INVALID ✗` — distinct from untrusted.
- `sc verify [<ref>] [--require]` — walks history from the tip (all
  parents, not first-parent only), reporting per-commit status and a
  summary; `--require` exits 1 if any commit is unsigned, untrusted, or
  invalid.

### Threat model honesty (documented in ADR + CLAUDE.md)

- Defends: history rewriting in clones/remotes (rewritten snapshots lack
  trusted signatures), attribution disputes.
- Does NOT defend: a trusted signer acting maliciously; anything about
  code quality; replay of legitimately-signed old snapshots into other
  contexts (a signature binds identity to snapshot, not snapshot to
  branch position).
- Amend/rebase/merge create NEW snapshot ids that start unsigned —
  re-sign deliberately (`sc sign`). This is correct, not a gap: the new
  object is a new claim.

## Testing & demo

- crypto: sign/verify round trip, domain separation (id signed under a
  different domain string fails), v2 keyfile parse + v1 rejection on
  signing with a clear error.
- Index: append/lookup/atomicity; gc prunes orphaned signatures (snapshot
  unreachable → index entry dropped → object pruned) and keeps live ones.
- Transfer: signatures round-trip clone/fetch/push over local AND ssh
  transports (SC_SSH shim path); git export/push reports
  `signatures_dropped`.
- CLI: log markers for all four states; verify --require exit codes;
  sign-then-verify; retroactive sign of an old commit.
- `demo/run_provenance_demo.sh`: keygen v2 ×2, trust alice; alice signs
  history; clone; verify clean in clone; REWRITE ATTACK in the clone
  (amend a mid-history... amend the tip); `sc verify --require` fails in
  the clone naming the unsigned rewrite while the original repo stays
  clean; retroactive `sc sign` by bob shows `?` until bob is trusted.

## Out of scope

Trust delegation/expiry (deferred, ROADMAP); signing refs/tags (no tag
objects exist); auto-sign config (`--sign` is explicit in MVP); mapping
sc signatures onto git commit signatures at the export boundary;
threshold/multi-sig policies.
