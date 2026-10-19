# ADR-0051: Rotating protected paths (`sc rewrap --rotate`)

- **Status:** Accepted (built)
- **Date:** 2026-10-19
- **Builds on:** ADR-0043 (randomized protected sealing), ADR-0027 (bulk rewrap), ADR-0019 (secret lifecycle), ADR-0026 (revocation)

## Context

`sc revoke` is standing-only, and `sc rewrap` replaces wrap lists: it drops a revoked recipient's wrap from the tip. Neither changes the DEK. A recipient revoked earlier who still holds the old wrap (a clone made before the revoke) keeps opening the tip's ciphertext, because the DEK that opens it has not changed. For secrets this is closed by `sc secret rotate` (fresh DEK). For protected paths ADR-0019 called rotation "security-meaningless" because convergent encryption derives the DEK from the plaintext. ADR-0043 removed that objection for randomized content and recorded rotate-for-paths as an unlocked follow-on.

## Decision

`sc rewrap --rotate` (`Repo::rewrap_with(.., rotate = true)`) re-seals every protected blob at the tip under a fresh random DEK and nonce, to exactly the rule's granted set plus escrow. It reuses the existing convergent-upgrade branch of rewrap, which already does the whole job: unwrap the blob's DEK with the identity, decrypt, `encrypt_path_randomized`, wrap the new DEK per recipient, retarget the tree entry, drop the old ciphertext's wrap entry once nothing references it, and record the working file in the stat cache so status stays clean.

- One command, one commit, one oplog record (`sc undo` reverts it), skip-and-report for entries the identity cannot open, exactly as a plain rewrap. An unopenable blob is left byte-for-byte as it was.
- It changes ciphertext ids, so the root tree changes. A plain rewrap over an all-randomized tip stays policy-only.
- Secrets are re-sealed with a fresh DEK by every rewrap already.
- Reports a separate `blobs_rotated` count; `blobs_resealed` stays the convergent upgrade count.
- All existing guards apply: private branches and partial clones refuse, and an in-progress merge, pick or rebase refuses.

## Consequences

- A recipient revoked before the rotation, holding an old wrap and DEK, can no longer open the tip's ciphertext. The test seals a file, grants and revokes a second recipient, shows a plain rewrap leaves their old DEK working, and shows a rotate closes it.
- **Rotation is not erasure.** Every earlier snapshot keeps the old ciphertext and its wraps, and content addressing keeps those reachable; anyone who fetched them can still open them. Rotating the underlying credential remains the real cutover for secret content.
- **Cost.** Every protected blob at the tip is rewritten, so the CAS gains one new blob per protected file per rotation and the old ones become gc-eligible only once nothing reaches them (history does). Rotation is a deliberate operation, not a routine one.

## Tests

`rewrap::tests::rotate_makes_the_tip_unreadable_with_a_revoked_recipients_old_dek` (plain rewrap leaves the old DEK working; dry-run reports without committing; rotate changes the id, closes the old DEK, keeps alice's plaintext, drops the old wraps, leaves status clean, rotates again to yet another id, and undoes) and `rotate_skips_a_path_the_identity_cannot_open_and_rotates_the_rest`. `demo/run_rewrap_demo.sh` step 7 proves it through the CLI.
