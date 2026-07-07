# ADR-0025: Protected merge & replay — perms-aware three-way with decrypt-on-demand

- **Status:** Accepted
- **Date:** 2026-07-06
- **Phase:** 15
- **Builds on:** ADR-0012 (three-way merge), ADR-0014 (encrypted paths),
  ADR-0019 (lifecycle/escrow), ADR-0024 (history editing)

## Context

Since P7, every merge/rebase/cherry-pick fails closed when any involved
tree carries a PROTECTED entry (`three_way` flattens trees without perms;
replaying ciphertext as plain blobs would corrupt it). The confidentiality
pillar therefore blocks the core collaboration workflow. P14 added the
replay toolkit, widening the gap.

## Decision

- **Id-level resolution on ciphertext is sound** because path encryption is
  convergent: equal plaintext ⇒ equal ciphertext blob id. Unchanged /
  one-side-changed / clean-delete protected cases resolve by id comparison,
  carrying ciphertext + wrapped DEKs (union when both sides know a blob),
  with no identity — a non-recipient can merge non-colliding protected
  branches.
- **Decrypt-on-demand for content divergence only.** Both-changed,
  delete-vs-modify, and perms-divergent protected paths require an
  authorized `--identity`; the plaintexts are diff3-merged and the output
  is re-encrypted before any CAS write via the same encrypt-and-reuse-
  prior-wraps helper `commit` uses (extracted; single-sourced).
- **Protection rules merge by union, fail-closed:** prefix union;
  recipient-set union per shared prefix. Nothing silently unprotects.
- **Secret registry replays** through rebase/cherry-pick via the existing
  `merge_secrets`; replay's `Empty` now means tree-empty AND
  registry-delta-empty, so secrets-only commits replay instead of skipping.
- Conflicted protected merges write plaintext markers only to the working
  tree of the identity-holder — P7's existing checkout trust boundary.

## Alternatives considered

- Decrypt-everything-first: contradicts the identity gate (trivial cases
  would demand a key) and churns wraps on untouched files.
- Working-tree-mediated merge: maximum reuse but dirties the tree on clean
  merges and breaks rebase's all-in-CAS atomicity.
- Conflict-on-any-protected-divergence (never decrypt): every concurrent
  edit becomes a manual conflict; weak capability.

## Consequences

- Merge/replay of protected content is identity-gated exactly where
  plaintext is required, and nowhere else.
- Re-encryption of merged content produces fresh wraps for new blob ids;
  prior-wrap reuse keeps unchanged content's encoding stable.
- Rule narrowing cannot happen via merge (union); explicit unprotect
  remains a future operation.
- **A prefix-rule revoke (`sc revoke <prefix> --recipient-id <id>`) is not
  durable against a union merge of any branch created before the revoke.**
  `union_prefixes` re-adds the revoked recipient's entry to the rule when
  that older branch is merged in, and every *future* commit under the
  prefix then seals fresh DEKs to them — content they never held a key for.
  This is distinct from the documented, harmless unchanged-blob wrap
  resurrection (ADR-0019): that resurrection only re-exposes a *past*
  ciphertext the recipient could already decrypt from history; this one
  grants access to *new* content going forward. It is spec-conformant
  (rule narrowing is an explicit deferred item, above) but currently
  undocumented behavior a caller must know about. Durable revocation needs
  the deferred rule-narrowing/tombstone follow-on (ROADMAP.md, Deferred).
  Until then, after a revoke, re-check `sc protect --list` following any
  merge and re-run `sc revoke` if the rule was re-widened.
  [Closed by ADR-0026 (P16): revocation tombstones (per-recipient
  last-writer-wins register) make this durable against merges of
  pre-revoke branches; the re-check/re-run workaround above is no longer
  needed. Note the surviving boundary: revoke still doesn't rotate
  ciphertext, so a recipient who already held a wrap can still decrypt
  pre-revoke content — see ADR-0026's Decision section.]

## Refinements during the build

Two review passes surfaced issues the design above didn't anticipate; all
are fixed in the shipped code (task history on `p15-protected-merge`), not
deferred.

1. **Decided-root persistence + HEAD-gated reads.** The design didn't
   specify how a *conflicted* protected merge/pick should resolve at
   completion time. The first implementation arbitrated by parent order
   ("ours" wins for absent protected files), which review found silently
   **reverted content the other side had already updated** — a data-loss
   bug, not a conflict. The fix persists the operation's decided tree
   (`.sc/MERGE_DECIDED_ROOT`, `.sc/PICK_DECIDED_ROOT`) alongside its
   `MERGE_HEAD`/`PICK_HEAD` marker; completion carries absent protected
   files forward *from the decided tree*, not from either parent. A second
   review pass then found that a decided-root file left behind by an
   abandoned/crashed operation could be read back and silently splice into
   an unrelated *later* completion — so reads and `sc gc`'s reachability
   walk are now gated on the corresponding in-progress HEAD file existing;
   the decided root is cleared in lockstep with the HEAD marker it
   accompanies.
2. **The I2 re-encrypt rule.** Protection-rule union can cause a path that
   was carried forward as **plaintext** (because it wasn't touched by the
   side that introduced or widened a matching rule) to newly match a
   protection rule at the landing snapshot. Left alone this breaks the
   invariant that a path's `PROTECTED` bit and its ciphertext-vs-plaintext
   state agree. The fix re-encrypts any such carried-PLAIN file through
   `encrypt_protected` at completion, so "protected in this snapshot" and
   "ciphertext in this snapshot" stay synonymous everywhere, not just on
   paths that were themselves edited.
3. **`Empty` redefined as a tri-delta.** P14's replay treated a commit as
   "nothing to replay" when its **tree** was unchanged from its parent.
   Under P15 that missed commits whose only change was a protection-rule
   edit or a secret-registry change with an unchanged tree — those were
   silently dropped during rebase/cherry-pick. `Empty` now requires the
   tree delta, the registry delta, **and** the protection-prefix delta to
   all be empty, so rules-only and secrets-only commits replay correctly.
4. **Pick-completion registry merge.** A cherry-pick that both conflicts
   *and* carries a secret-registry change had a latent hole: the
   conflict-completion path resolved the tree conflict but dropped the
   picked commit's registry delta. Completion now merges the picked
   commit's registry change via the same `merge_secrets` used elsewhere,
   closing that combined-case gap.
5. **`decrypt_with` distinguishes corruption from unauthorized.** The
   initial cut reported any decrypt failure — including a truncated or
   bit-flipped ciphertext object — as `Error::NotAuthorized`, which is
   misleading (an authorized recipient with a corrupt object isn't
   "unauthorized"). `decrypt_with` now surfaces corruption as a distinct
   crypto error, reserving `NotAuthorized` for the case where no wrap
   unwraps under the supplied identity.
6. **`union_wraps` output sorted.** Wrap-set union initially preserved
   whatever order the two input sets happened to have. Because wraps are
   encoded into the canonical object bytes that determine content
   addressing, non-deterministic ordering would make the same logical
   merge hash differently depending on operand order. `union_wraps` (like
   `union_prefixes`) now sorts its output deterministically.
7. **`Zeroizing` re-exported through the crypto quarantine.** Merge/replay
   code outside `crates/crypto` needed to name the zeroizing-on-drop buffer
   type returned by decrypt helpers. Rather than let `repo` add its own
   `zeroize` dependency (breaking the "RustCrypto stays quarantined in
   `crypto`" rule), `crates/crypto` re-exports `zeroize::Zeroizing` as a
   type alias — the dependency itself stays quarantined; only the type name
   crosses the boundary.
