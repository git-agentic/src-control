# ADR-0017: Accidental-plaintext secret scanner at commit time

- **Status:** Proposed
- **Date:** 2026-06-25
- **Phase:** 5
- **Adapts:** [git.agentic ADR-0013](https://github.com/git-agentic/git.agentic)
  (pattern + entropy secret scanner as a `put_raw` pre-hook)
- **Complements:** ADR-0008/0009/0010 (Phase 2 committed secrets)

## Context

Phase 2 lets a user *deliberately* commit secrets as envelope-encrypted objects.
The dual risk is the *accidental* one: a developer commits a `.env`, an API key,
or a private key in **plaintext** as an ordinary file. Once committed and
(eventually) pushed, the secret is disclosed. Phase 2 does nothing about this —
it is the opposite problem.

The sibling project git.agentic ships a pattern + entropy scanner that
hard-rejects secret-bearing blobs at write time (its ADR-0013). The same
mechanism fits src-control, with one src-control-specific wrinkle: our store
intentionally holds high-entropy **ciphertext** (Phase 2 `Secret` objects, and
P7 encrypted-path blobs). A naive entropy scanner would flag exactly the objects
we deliberately encrypted.

## Decision

Add a **pattern + Shannon-entropy scanner** that runs at commit time and
**hard-rejects** plaintext secrets:

1. **Where it runs.** Scan plaintext file blobs in the commit path before they are
   written — in `scl-repo` (`Repo::commit`, and the working-tree snapshot path),
   the choke point through which working-tree content enters the store. A pure,
   dependency-light `scan(bytes, &allowlist) -> Vec<Hit>` lives in its own module
   (`scl-repo::scanner` + a compile-time `scanner_patterns`), independently
   testable.
2. **Exemptions (src-control-specific).** The scanner runs **only on plaintext
   `Blob` content**. `Secret` objects and P7 encrypted-path objects are
   **never** scanned — they are ciphertext by construction, and scanning them
   would be both pointless and a guaranteed entropy false-positive.
3. **Detection.** A curated, compile-time `RegexSet` of high-precision token
   patterns (GitHub/AWS/Anthropic/OpenAI/Stripe/GCP keys, PEM private-key
   headers) in one linear pass, plus a Shannon-entropy heuristic flagging
   contiguous base64-alphabet runs ≥ 20 chars with entropy > 4.5 bits/char.
4. **On a hit.** Return `Error::SecretDetected { hits }` and abort the commit; the
   offending content never reaches the store. **No override flag** — the fix is to
   remove the secret from the file (and commit it properly via `sc secret` if it
   belongs in the repo).
5. **Allowlist for false positives.** A `.sc/scanner-allowlist.toml` lists exact
   **BLAKE3 blob ids** (reusing `ObjectId`, 64 hex chars) that are exempt — scoped
   to one specific blob's content, never a pattern. Loaded at repo open.

## Consequences

- Closes the accidental-plaintext gap, making src-control's secret story complete:
  deliberate secrets encrypted (Phase 2/P7), accidental secrets rejected (P5).
- Reuses the project's BLAKE3 `ObjectId` for the allowlist — one hash function,
  no new crypto.
- Adds a `regex` dependency to `scl-repo` (not to `core`, keeping the object model
  minimal); the scanner module is self-contained and unit-testable without IO.
- Hard rejection with no override is deliberate (matches git.agentic): an escape
  hatch is the thing operators enable and forget. If the fix-the-input loop proves
  too painful, that is a later, explicit ADR.
- The exemption rule couples the scanner to object kinds (Blob vs Secret vs
  encrypted) — it must be updated when P7 adds encrypted-path objects so those are
  exempted too.

## Alternatives considered

- **Scan at `core::Store::put` (lowest layer), like git.agentic.** Universal
  coverage for any future direct-put caller, but pushes a `regex` dependency into
  `core` and would require the kind-exemption logic there. src-control has no SDK
  /direct-put surface today — working-tree content only enters via the commit
  path — so scanning in `scl-repo` is sufficient and keeps `core` lean. Revisit if
  a direct object-write API is ever exposed.
- **Soft warn instead of hard reject.** Warnings are ignored; the docs/posture
  commit to rejection. Rejected.
- **External tool (gitleaks) subprocess.** Heavier (binary management, latency);
  a native `RegexSet` + one entropy pass is enough for v1. Rejected.
- **Regex/pattern allowlist.** Invites over-broad exemptions; hash-scoped
  allowlist cannot accidentally whitelist future content. Rejected.
