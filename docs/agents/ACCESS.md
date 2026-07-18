# Access inventory

Who — and what — holds which privilege over this project. One page, kept
current; [`incident-response.md`](../security/incident-response.md) depends on
it as the revocation checklist. Written as OSTIF-audit follow-up T-14 (G-012).

## Cryptographic custody (most sensitive first)

| Privilege | Holder | Notes |
|---|---|---|
| **Escrow keys** | Toni Bergholm | A standing decrypt privilege over every committed secret and protected path escrow-wrapped to them, and **every private branch before publish** (ADR-0044). Categorically more sensitive than repo-admin. Managed via `sc escrow`; rotation ≠ erasure. |
| `scl` identity/signing keys | Toni Bergholm | Kept **outside any working tree** (scanner footgun; a key committed under a private branch is sealed in). Sign commits (P22); compromise playbook: incident-response class 1. |

## Humans

| Privilege | Holder | Notes |
|---|---|---|
| GitHub org owner (`git-agentic`) | Toni Bergholm (`tonibergholm`) | Org 2FA requirement **enforced** since 2026-07-18 (see [`opsec-baseline.md`](../security/opsec-baseline.md)). |
| Repo admin (`git-agentic/src-control`) | `tonibergholm`, `tonibergholm-codento` | Both admin. Control rulesets, security toggles, secrets. |
| Reviewer (required PR approver) | `tonibergholm`, `tonibergholm-codento` | Since 2026-07-18 the `main` ruleset requires **1 approval** from a principal other than the last pusher, so the two accounts review each other's PRs (closes audit G-032). |
| `git-agentic.com` DNS/registrar | Toni Bergholm | Out-of-repo credential. |
| crates.io publish rights | — (N/A) | Workspace is `publish = false`; no crates.io tokens exist. Revisit at first release (audit T-24 trigger). |
| Security-report handler | Toni Bergholm | Per [`vulnerability-response.md`](../security/vulnerability-response.md). |

## Non-human principals

| Principal | Scope | Notes |
|---|---|---|
| `GITHUB_TOKEN` — `ci.yml` | `contents: read` | Ephemeral per-run. |
| `GITHUB_TOKEN` — `codeql.yml` | `contents: read` top-level; analyze job adds `security-events: write`, `actions: read` | Ephemeral per-run. |
| `GITHUB_TOKEN` — `audit.yml` | `contents: read`, `checks: write`, `issues: write` (job-scoped as of audit T-20) | Files RustSec findings as public issues. |
| `GITHUB_TOKEN` — `scorecard_analysis.yml` | `read-all` top-level; job adds `security-events: write`, `id-token: write` | Publishes Scorecard results. |
| AI agents (Claude Code et al.) | `gh` CLI under the maintainer's auth: issue/PR create, comment, label, close; local commit + push | Operate the public triage pipeline (`issue-tracker.md`). **Excluded** from draft security advisories and private reports; security fixes need distinct human review (see vulnerability-response.md). Compromise playbook: incident-response class 2. |
| Dependabot | Version + security update PRs (cargo, npm, github-actions) | PRs merge only through the standing required checks. |

## Maintenance

Update this file in the same PR as any change that grants, widens, or revokes a
privilege (new workflow permission, new maintainer, new publish channel, new
escrow recipient).
