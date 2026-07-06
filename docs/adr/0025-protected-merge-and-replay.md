# ADR-0025: Protected merge & replay — perms-aware three-way with decrypt-on-demand

- **Status:** Proposed
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
