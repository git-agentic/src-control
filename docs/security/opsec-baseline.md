# Operational-security baseline

The standing rules for this project's development and CI infrastructure, so
they survive as policy rather than habit. Written as OSTIF-audit follow-up
T-20 (G-025).

## CI

- **GitHub-hosted ephemeral runners only.** No self-hosted runners — adding one
  creates a persistent trust boundary this project has deliberately avoided.
- **`GITHUB_TOKEN` is the only CI credential.** No long-lived cloud keys, PATs,
  or deploy tokens in Actions secrets. Any new secret needs a written
  justification in [`docs/agents/ACCESS.md`](../agents/ACCESS.md) first.
- **Least-privilege, job-scoped permissions.** Workflow-level `permissions:`
  stays read-only (`contents: read` / `read-all`); write scopes are granted
  per job, only where used (audit T-20 scoped `audit.yml`'s
  `checks: write` + `issues: write` to the job level).
- **Third-party actions are SHA-pinned** with a version comment; Dependabot
  maintains the pins (audit T-2). New actions enter SHA-pinned or not at all.
- **Merges to `main` are ruleset-gated**: PR required, four required status
  checks, up-to-date branch, no force-push/deletion, no bypass actors.

## Accounts and devices

- **Org 2FA requirement: PENDING.** `two_factor_requirement_enabled` is
  currently `false` on the `git-agentic` org. Maintainer action: enable it in
  org settings (Settings → Authentication security) after confirming the owner
  account has 2FA. ☐ done as of ____. (An automated attempt was intentionally
  not forced through — org-wide auth policy is a human call.)
- Maintainer GitHub account uses 2FA and per-device SSH keys; identity/signing
  keys for `scl` live outside any working tree (see ACCESS.md).
- Development machines: full-disk encryption and OS auto-update expected; no
  further device policy is codified for a solo project (revisit at second
  maintainer).

## Repository security features (all enabled 2026-07-18, audit Now-tier)

Secret scanning + push protection, Dependabot alerts + security updates,
private vulnerability reporting, CodeQL (3 languages), Scorecard (weekly).
Disabling any of these is a policy change: PR + note here, not a quiet toggle.
