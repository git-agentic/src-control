# Native hosting/platform strategy

Research date: 2026-07-14

## Recommendation

Build a narrow, native collaboration product for `sc`, but do not begin by
cloning GitHub. The first product should make the capabilities that Git hosting
cannot represent visible and usable: snapshot comparison, agent-session
provenance, signature status, authorization-aware trees, protected paths, and
the private-branch publish workflow.

Keep GitHub interoperability as the adoption bridge. The repository's current
positioning explicitly says that `sc` builds on and interoperates with Git
rather than replacing it wholesale, and it already supports hosted Git through
the mirror bridge ([README](../../README.md)).

## What the referenced products provide

- [Trees](https://trees.software/) and [Diffs](https://diffs.com/) are open-source
  presentation components, not repository hosting. Their source packages are
  Apache-2.0 licensed: [`@pierre/trees`](https://github.com/pierrecomputer/pierre/blob/main/packages/trees/package.json)
  and [`@pierre/diffs`](https://github.com/pierrecomputer/pierre/blob/main/packages/diffs/package.json).
  Diffs supports unified/split layouts, comments and annotations, line
  selection, conflict-resolution UI, and arbitrary-file comparison, which is a
  particularly good fit for snapshot comparison rather than only Git patches
  ([Diffs product page](https://diffs.com/)).
- [Code Storage](https://code.storage/) describes itself as API-first,
  white-label **Git** infrastructure for applications. It offers native Git
  clone/push/fetch endpoints, SDK read/write access, webhooks, ephemeral
  branches, in-memory writes, and GitHub synchronization. This is adjacent
  infrastructure, not a native store for `sc` objects. Using it as the source
  of truth would lose or externalize `sc` concepts that Git cannot encode,
  including sealed private branches and native transcript/signature objects.
- GitHub's differentiating surface is substantially larger than file and diff
  rendering. Pull requests combine branch comparison with discussion, review,
  and merge; reviews support comments, approvals, requested changes, and
  suggested changes ([GitHub pull request docs](https://docs.github.com/en/pull-requests),
  [review docs](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/about-pull-request-reviews)).
  Repository governance adds protected branches and required status checks
  ([GitHub repository docs](https://docs.github.com/en/repositories)). A full
  competitor also implies identity, organizations, permissions, issues,
  automation, integrations, notifications, audit, billing, abuse handling, and
  multi-tenant operations.

## Suggested scope

### Stage 1: public proof and browser

- Host one or a few public `sc` repositories.
- Show branches, snapshots, history, signatures, and transcript-presence
  metadata.
- Browse trees/files with Trees and compare any two snapshots with Diffs.
- Show protected or sealed content as intentionally unavailable when the viewer
  lacks an identity; never substitute ciphertext as if it were source text.
- Provide `sc clone` instructions and GitHub mirror links.

This is a product/demo surface, not yet a forge.

### Stage 2: native change review

- Introduce a small "change" object: base ref/id, proposed ref/id, state,
  reviewers, comments, approvals, and checks.
- Add line comments, signature/provenance policy, conflict preview, and merge.
- Make agent sessions first class: show the agents/workspaces that produced a
  change and their sealed transcript attestations.
- Add the private-branch publish gate as a distinct workflow rather than
  forcing it into ordinary Git pull-request semantics.

### Stage 3: hosting only after demand

- Multi-repository routing, accounts/organizations, repository ACLs, quotas,
  audit logs, backups, availability, billing, and operational isolation.
- CI/webhooks/issues only when validated by users; until then, integrate with
  GitHub rather than duplicating its ecosystem.

## Security boundary

A hosted UI must not silently become a universal recipient for protected
content. Safe initial choices are:

1. Render public metadata/content server-side and leave protected content
   opaque.
2. Later, decrypt in the browser with a user-controlled identity that is never
   uploaded to the service.
3. For a trusted enterprise deployment, allow the service to be added as an
   explicit recipient, making that trust decision visible and auditable.

This boundary should be decided before building authenticated private-content
views; it affects the API, threat model, and product promise.

## Build/buy conclusion

Use Trees and Diffs for the UI after a small technical spike. Build the native
`sc` read/review API because the existing HTTP server is a sync wire protocol,
not a browser API. Treat Code Storage as market validation and possible Git
mirror infrastructure, not the native backend. Continue using GitHub for issue
tracking, CI, discovery, and public mirrors while the differentiated native
workflow is validated.
