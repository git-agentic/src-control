# Gap Analysis: src-control repository vs. OSTIF/Least Authority Security Best Practices Guide

## Comparison Direction

**Current state → Desired state** (unidirectional, as instructed).

- Current state: the `src-control` repository at
  `/Users/tonibergholm/Developer/claude/src-control` (commit `d7106e5` at time of
  analysis, plus one untracked file `docs/research/cryptography-audit-options.md`).
- Desired state: the OSTIF/Least Authority "Security Best Practices Guide"
  (`README.md`, `01-introduction.md` … `07-milestones.md`), cloned locally to
  `/private/tmp/claude-501/.../scratchpad/ostif-guide/`.

Where a desired-state item concerns GitHub repository configuration not visible
in the file tree (branch protection, secret scanning, private vulnerability
reporting toggle, dependabot security updates), this analysis used `gh api` to
query the live `git-agentic/src-control` GitHub repository directly — these
findings are **verified**, not inferred, and are cited as such. Anything not
checkable even via `gh api` (e.g., org-level settings, mailing-list
subscriptions, individual maintainers' inboxes) is marked **unverifiable from
repo/API** and classified as Implicit.

## Scope

Comparison areas follow the guide's six practice areas plus its two framing
chapters (Introduction, "What to do next" — the latter file does not exist in
the cloned guide and was not compared):

1. Private security reporting pipeline (Ch. 2)
2. Internal vulnerability response policy (Ch. 3)
3. Development/build best practices (Ch. 4)
4. Up-to-date security (Ch. 5)
5. Updated knowledgebase (Ch. 6)
6. Milestones (Ch. 7)

Excluded: `08-what-next.md` is linked from the guide's README and chapter 7 but
was not present in the cloned guide directory, so it could not be compared —
noted under "Areas Needing Separate Analysis" (not scored as a finding, since
there is no retrievable desired-state content to compare against).

Files/areas examined in the current state: `SECURITY.md`, `CONTRIBUTING.md`,
`CODE_OF_CONDUCT.md`, `LICENSE`, `README.md`, `CLAUDE.md`, `ARCHITECTURE.md`,
`ROADMAP.md` (incl. `## Deferred`), `docs/THREAT-MODEL.md`, `docs/adr/*`,
`docs/agents/issue-tracker.md`, `docs/agents/triage-labels.md`,
`docs/research/cryptography-audit-options.md`, `.github/workflows/{ci,codeql,audit}.yml`,
`.github/dependabot.yml`, `Cargo.toml`/`Cargo.lock`, `apps/desktop/package.json`
and CI coverage of it, `git log` (RustSec/audit/CodeQL commit history), and the
live GitHub repository's `security_and_analysis` block and branch-protection API.

## Summary

Compared the src-control repository's security posture, tooling, and documentation against all
six OSTIF/Least Authority Security Best Practices Guide chapters and their self-check items,
current state toward desired state. The project substantially satisfies chapter 2
(reporting pipeline) and parts of 4/5 (RustSec/CodeQL scanning, dependabot cargo updates), but
has concrete gaps in code-review enforcement, GitHub-native security tooling (secret scanning,
dependabot security updates, private vulnerability reporting, branch protection — all
confirmed disabled or unenforced via the live API), fuzzing/property-based testing, reproducible
builds, OpenSSF Scorecard, npm-side supply-chain scanning for the desktop app, SBOM, an internal
security-incident response process, and an explicit access-privilege/PII inventory.

| Category | Count | Description |
|----------|-------|-------------|
| Missing | 15 | Elements in desired state with no current state correspondence |
| Partial | 8 | Elements present in both but incompletely covered |
| Divergent | 1 | Elements addressing same concern in incompatible ways |
| Implicit | 4 | Assumed capabilities neither confirmed nor denied |

Full analysis written to: `/Users/tonibergholm/Developer/claude/src-control/docs/audit/gap-analysis-source.md`

## Findings

**GAP-001: No SAST/fuzzing/property-based testing**
- **Category:** Missing
- **Feature/Behavior:** Ch. 4 self-check: "A wide range of testing (e.g., ... testing edge-cases and properties (fuzzing and property-based testing)".
- **Current State:** `grep -rn "fuzz\|proptest\|quickcheck\|property"` across `crates/**/*.rs` and `Cargo.toml` returns only prose comments referencing the word "property" (e.g. `crates/repo/src/rewrap.rs:37`, `crates/repo/src/repo.rs:5337`) — no `proptest`/`quickcheck`/`cargo-fuzz`/`afl` dependency, harness, or fuzz target anywhere in the workspace. `CONTRIBUTING.md:23-26` lists only `cargo test`, `cargo fmt`, `cargo clippy` as the required local bar; `.github/workflows/ci.yml:47-48` runs `cargo test --workspace --all-targets` only.
- **Desired State:** `04-follow.md:7`: "A wide range of testing (e.g., adding integration testing, testing edge-cases and properties (fuzzing and property-based testing), and adding integrated testing in CI".

**GAP-002: OSS-Fuzz not integrated**
- **Category:** Missing
- **Feature/Behavior:** Ch. 5 self-check: "OSS-Fuzz" as a subscribed/utilized free tool.
- **Current State:** No `.clusterfuzzlite/`, `oss-fuzz` project file, or fuzz target directory exists anywhere in the repository (`find . -iname "*fuzz*"` under crates/ returns nothing beyond prose comments, per GAP-001).
- **Desired State:** `05-up-to-date.md:29`: self-check item "OSS-Fuzz" under SAST tooling.

**GAP-003: No reproducible-build tooling or verification**
- **Category:** Missing
- **Feature/Behavior:** Ch. 4 self-check: "Determine viability of allowing reproducible builds."
- **Current State:** No reference to `reproducible-builds.org`, deterministic-build flags, `--remap-path-prefix`, or build-attestation tooling anywhere in `Cargo.toml`, CI workflows, or `docs/`. `grep -rn -i "reproducible"` across the repo (excluding `target/`) returns zero matches.
- **Desired State:** `04-follow.md:15`: "If feasible for your project, consider enabling reproducible builds... allowing the ability to prove nothing has been injected during compilation via comparison to the original build."

**GAP-004: No OpenSSF Scorecard or OWASP ASVS self-guided review**
- **Category:** Missing
- **Feature/Behavior:** Ch. 4 self-check: "Do Self Guided Security Reviews — OpenSSF Security Scorecard / OWASP Application Security Verification Standard."
- **Current State:** `grep -rn -i "scorecard\|ossf\|asvs" .` (excluding `target/`, `node_modules/`) returns zero matches; no `ossf/scorecard-action` workflow exists in `.github/workflows/` (only `ci.yml`, `codeql.yml`, `audit.yml` are present).
- **Desired State:** `04-follow.md:24-26`: self-check "Do Self Guided Security Reviews — [ ] OpenSSF Security Scorecard — [ ] OWASP Application Security Verification Standard."

**GAP-005: SBOM not produced**
- **Category:** Missing
- **Feature/Behavior:** Ch. 6 self-check: "Create SBOM (if relevant)."
- **Current State:** `find . -iname "*sbom*"` (excluding `target/`, `node_modules/`) returns no results; no `cargo-cyclonedx`, `cargo-sbom`, or SPDX/CycloneDX file/workflow step exists. `Cargo.lock` exists (dependency graph) but is not published or transformed into a shareable SBOM artifact.
- **Desired State:** `06-kb.md:9,18-19`: "Creating a Statement Bill of Materials (‘SBOM’)..." self-check "Create SBOM (if relevant) — Utilize OS tools like awesome-sbom to determine if a SBOM is right for your organization."

**GAP-006: No npm/frontend dependency audit in CI**
- **Category:** Missing
- **Feature/Behavior:** Ch. 4 self-check: "Reviewing and updating dependencies... integrating dependency checks and static analysis in CI, wherever possible" — applies to every ecosystem in the project, including the Tauri/React frontend.
- **Current State:** `apps/desktop/package.json` declares a full npm dependency tree (React 19, Vite 8, TypeScript 7, `@pierre/*`, Tauri JS bindings). `.github/workflows/ci.yml` only builds/tests the Rust workspace (`cargo test --workspace --all-targets`, `cargo fmt`, `cargo clippy`) — grep for `npm`/`node`/`desktop` in `.github/workflows/*.yml` returns no matches. No `npm audit`, `npm ci`, or JS build/test step exists in any workflow. `.github/dependabot.yml:1-40` configures only `package-ecosystem: cargo` and `package-ecosystem: github-actions` — no `npm` ecosystem entry for `apps/desktop`.
- **Desired State:** `04-follow.md:9`: "Reviewing and updating dependencies, as well as integrating dependency checks and static analysis in CI, wherever possible."

**GAP-007: GitHub secret scanning and push protection disabled**
- **Category:** Missing
- **Feature/Behavior:** Ch. 4's "internal operational security, including... internal best practices on handling secrets" and Ch. 5's automated-tooling posture both imply repository-native secret-leak defenses as a baseline control.
- **Current State:** Live `gh api repos/git-agentic/src-control` query returns `"security_and_analysis": {"secret_scanning": {"status": "disabled"}, "secret_scanning_push_protection": {"status": "disabled"}, "secret_scanning_non_provider_patterns": {"status": "disabled"}, "secret_scanning_validity_checks": {"status": "disabled"}}` (verified via API, not inferred). The project does have its own commit-time secret scanner (P5, `docs/adr/0017-secret-scanner.md`) that operates on `sc`-tracked content, but that is orthogonal to GitHub's scanning of the Git-hosted mirror/export path and does not cover the GitHub repository surface itself.
- **Desired State:** `04-follow.md:11`: "Reviewing the internal operational security, including, for example, internal best practices on handling secrets."

**GAP-008: Dependabot security updates disabled at the GitHub repository level**
- **Category:** Missing
- **Feature/Behavior:** Ch. 5 self-check: "Are you able to automate updates for your project?" and the `dependabot-core` reference.
- **Current State:** Live API query: `"dependabot_security_updates": {"status": "disabled"}`. `.github/dependabot.yml` configures scheduled version-update PRs (weekly, cargo + github-actions ecosystems) but the separate GitHub *security*-update toggle (auto-PRs specifically for vulnerability alerts, independent of the `dependabot.yml` schedule) is off.
- **Desired State:** `05-up-to-date.md:15,25,30`: "Enabling automation in updates when securely possible..." self-check "Are you able to automate updates for your project?" and tool reference `github.com/dependabot/dependabot-core`.

**GAP-009: Code review before merge is practiced but not enforced on `main`**
- **Category:** Partial
- **Feature/Behavior:** Ch. 4 self-check item: "Adhering to best practices in code review in the development process (utilizing GitHub pull requests and requiring code reviews before merging)."
- **Current State:** `git log` shows the project does route changes through PRs in practice (e.g. commit `d7106e5` is `(#70)`, `0d27dfa` is `(#69)`) — the GitHub-pull-request half of the recommendation is present. But live `gh api repos/git-agentic/src-control/branches/main/protection` returns `404 {"message":"Branch not protected"}`: there is no required-review rule, no required-status-check rule, and nothing technically prevents a direct push to `main` bypassing review entirely. The practice exists; the enforcement does not.
- **Desired State:** `04-follow.md:8`: "Adhering to best practices in code review in the development process (utilizing GitHub pull requests and requiring code reviews before merging)."

**GAP-010: No internal vulnerability-response / triage-ticketing documentation**
- **Category:** Missing
- **Feature/Behavior:** Ch. 3: an internal, documented process for triaging and remediating a received vulnerability report (responsible-member assignment, bug-tracking documentation, remediation planning, third-party communication, verification with the researcher).
- **Current State:** `SECURITY.md:31-59` documents the *external* reporting channel and *timeline commitments* (3-day ack, 7-day status, 90-day coordinated disclosure) but nowhere documents the *internal* steps a maintainer follows on receipt: no named "responsible team member" role, no reference to how a report gets into GitHub Issues/bug-tracking (the standard `docs/agents/issue-tracker.md` process is generic and does not mention security reports or private handling), no remediation-planning or third-party-communication procedure, no verification-with-researcher step documented anywhere in `docs/`.
- **Desired State:** `03-response.md:7-16`: "project teams should create internal processes for handling the reported issues... Assigning responsible team members... Acknowledging the report... Adding the reported vulnerability to any internal bug-tracking or ticketing system... Triaging steps... Planning remediation... Planning any needed outside communication... Performing the verification of the remediation."

**GAP-011: No documented security-incident response process**
- **Category:** Missing
- **Feature/Behavior:** Ch. 3's second half: an internal process for handling security *incidents* (supply-chain attacks, malware campaigns, infrastructure compromise, data breaches) distinct from vulnerability *reports*.
- **Current State:** No document in `docs/` (including `docs/THREAT-MODEL.md`, which is scoped to cryptographic/protocol boundaries, not operational incident response) addresses what happens if, e.g., a maintainer's signing key is compromised, a dependency is found backdoored post-hoc, or `git-agentic.com`/the GitHub org account is compromised. `grep -rn -i "incident"` across `docs/` and root markdown files returns no process document.
- **Desired State:** `03-response.md:18-23`: "We recommend introducing an internal process for handling security incidents, including but not limited to supply-chain attacks, malware campaigns... infection or other attacks on the project's development or production systems, and data breaches."

**GAP-012: No documented list of access privileges**
- **Category:** Missing
- **Feature/Behavior:** Ch. 6 self-check: "List of access privileges."
- **Current State:** No document enumerates who holds GitHub org/repo admin, npm/crates.io publish rights, DNS/domain control for `git-agentic.com`, or signing-key custody. `docs/agents/domain.md` and `docs/agents/issue-tracker.md` describe process conventions, not privilege inventories. (The live API shows the querying credential has `"permissions": {"admin": true, ...}` for one account, but no repo document records this or any other maintainer's access level.)
- **Desired State:** `06-kb.md:17`: self-check "List of access privileges."

**GAP-013: No security-announcement subscription documentation**
- **Category:** Missing
- **Feature/Behavior:** Ch. 5 self-check: subscription to CVEs and security-announcement mailing lists for languages, libraries, dependencies, and tools.
- **Current State:** No document (README, CONTRIBUTING, THREAT-MODEL, or a dedicated ops doc) records that a maintainer is subscribed to RustSec/rust-lang security announcements, crates.io advisories beyond what `cargo-audit`'s live DB fetch covers, Tauri security advisories, or GitHub's own security-advisory feed. The `audit.yml` workflow's daily `cargo-audit` run (`.github/workflows/audit.yml:17-20`) provides automated *detection* of RustSec advisories but is not itself evidence of a human subscription/awareness practice for the broader ecosystem (Node/npm/Tauri CVEs, OS-level toolchain CVEs).
- **Desired State:** `05-up-to-date.md:9-10,20-24`: "Are you subscribed to relevant CVEs? Are you subscribed to the security announcements mailing lists for all languages, libraries, and dependencies related to your project, tools and anything else relevant to it?" self-check enumerates Languages/Libraries/Dependencies/Tools separately.

**GAP-014: Private vulnerability reporting (GitHub feature) not confirmed enabled**
- **Category:** Missing
- **Feature/Behavior:** Ch. 2's named example channel: "Private vulnerability reporting via Github."
- **Current State:** `SECURITY.md:34-38` *references* GitHub's private vulnerability reporting as an accepted channel ("or GitHub's private vulnerability reporting... on this repository"), but the live `gh api repos/git-agentic/src-control/security-advisories` call succeeds and returns `[]` (an empty list, meaning the endpoint is reachable, which happens whether or not the private-reporting *toggle* is on — the toggle itself is a repo setting not exposed by this endpoint and not queryable without a scope this session's token lacks). Combined with `dependabot_security_updates` and `secret_scanning` both being `disabled` in the same `security_and_analysis` block (GAP-007/GAP-008), and GitHub's UI groups the "Private vulnerability reporting" toggle in that same settings panel, there is a reasonable inference — not proof — that it may also be off. Marking this Missing rather than Implicit because SECURITY.md's own text presents it as a currently-usable channel, which is precisely the claim that cannot be verified from available API scope.
- **Desired State:** `02-pipeline.md:8`: "Private vulnerability reporting via Github" listed as a recommended pipeline mechanism.

**GAP-015: No legal safe-harbor / security-research authorization language**
- **Category:** Partial
- **Feature/Behavior:** Ch. 2's disclosure-policy content list: "Legal authorization for security research."
- **Current State:** `SECURITY.md` covers reporting channel, expected report contents, and response timelines (lines 31-59) but contains no statement authorizing good-faith security research (e.g., "we will not pursue legal action against researchers acting in good faith and within this policy"), and no reference to consulting legal counsel.
- **Desired State:** `02-pipeline.md:18-27`: disclosure policy should cover "Legal authorization for security research" and "we recommend that project teams consult their legal team to ensure compliance with the applicable law."

**GAP-016: No `security.txt` at a well-known location**
- **Category:** Missing
- **Feature/Behavior:** Ch. 2's mirroring recommendation: "You can also mirror this on your website at `/.well-known/security.txt` as per RFC 9116."
- **Current State:** `find . -iname "security.txt" -o -iname ".well-known"` returns no results in the repository. Since `git-agentic.com` is an external website (referenced as the GitHub repository's homepage field) not hosted from this repo, this is only a partial check — but no `security.txt` template or generation step exists in-repo either, so there is nothing in the current state feeding such a file even if the website is external.
- **Desired State:** `02-pipeline.md:18`: "You can also mirror this on your website at `/.well-known/security.txt` as per RFC 9116."

**GAP-017: No bug-bounty-program statement (presence or explicit absence)**
- **Category:** Partial
- **Feature/Behavior:** Ch. 2's disclosure-policy content list: "Existence or absence of a bug bounty program, along with its conditions."
- **Current State:** `SECURITY.md` does not mention a bug bounty program at all, in either direction (no statement that one exists, and no explicit statement that one does not, which the guide asks for as one of the required policy elements).
- **Desired State:** `02-pipeline.md:24`: "Existence or absence of a bug bounty program, along with its conditions."

**GAP-018: No request for reporter non-disclosure to third parties**
- **Category:** Partial
- **Feature/Behavior:** Ch. 2's disclosure-policy content list: "Request for non-disclosure to third parties."
- **Current State:** `SECURITY.md:53-55` commits the *project* to a 90-day coordinated-disclosure timeline, but nowhere asks the *reporter* to hold the report in confidence until a fix ships or the window elapses — the guide asks for both halves of that coordination to be stated explicitly, and only the project's own commitment is present.
- **Desired State:** `02-pipeline.md:21`: "Request for non-disclosure to third parties" listed as a required disclosure-policy element alongside timeline and legal authorization.

**GAP-019: `SECURITY.md` contains stale claims relative to shipped phases**
- **Category:** Divergent
- **Feature/Behavior:** Ch. 6's documentation-currency requirement: "Documentation that is current needs to detail the function and safe usage of a project... It should be easily read, well defined."
- **Current State:** `docs/research/cryptography-audit-options.md:139-140` (the project's own newly authored research note) states explicitly: "Reconcile `SECURITY.md` with the current P32 TLS and P33 randomized-protection design before soliciting bids; it currently contains stale pre-P32/P33 claims." This is the project's own internal admission of a documentation-currency defect, which directly contradicts the guide's freshness requirement — not merely an absence, but an acknowledged drift between shipped capability (P32 TLS, P33 randomized protection per `docs/THREAT-MODEL.md:16` and ADR-0042/0043) and what `SECURITY.md` currently asserts.
- **Desired State:** `06-kb.md:7`: "Documentation that is current needs to detail the function and safe usage of a project, its security disclosure process and goals."

**GAP-020: No documented list of third-party libraries/tools as project documentation**
- **Category:** Partial
- **Feature/Behavior:** Ch. 6 self-check: "List of third party libraries in project" and "List of tools, security practices, goals, etc."
- **Current State:** `CLAUDE.md`'s "Stack & tooling" section (lines ~19-27) names *some* key dependencies (`blake3`, `thiserror`, `hex`, `gix`, `clap`, `anyhow`, RustCrypto AEAD/X25519) as prose explaining architectural quarantine rules, not as a complete, purpose-built inventory; the full list lives only implicitly in `Cargo.lock` (160KB, not meant for human consumption) and `apps/desktop/package.json`. There is no single "third-party libraries and tools" document a user/auditor can read end-to-end, and the npm-side dependency tree is not mentioned in `CLAUDE.md` at all.
- **Desired State:** `06-kb.md:15-16`: self-check "List of third party libraries in project" / "List of tools, security practices, goals, etc."

**GAP-021: No explicit "does the project store PII" statement**
- **Category:** Missing
- **Feature/Behavior:** Ch. 7 self-check: "Does your project store any user PII?"
- **Current State:** `grep -rn -i "PII\|personal data\|GDPR"` across `docs/`, `CLAUDE.md`, `ARCHITECTURE.md` returns zero matches. Given the project's nature (a VCS with committed-secrets and per-file-encryption features whose whole purpose is storing sensitive user-supplied data — secrets, protected file content, private-branch content), an explicit PII/sensitive-data-exposure statement is a natural fit but does not exist as a standalone, findable assessment.
- **Desired State:** `07-milestones.md:29`: self-check "Does it store any user PII?"

**GAP-022: No documented milestone/release-triggered security-review cadence**
- **Category:** Partial
- **Feature/Behavior:** Ch. 7: "Maintainers ought to think ahead about when security efforts can be most impactful... changed aspects of a given project... Improvements or releases to a project that change permissions or features."
- **Current State:** `ROADMAP.md`'s per-phase entries (e.g., P28 "Security hardening sweep" at ROADMAP.md ~379-390) show *reactive* security-focused phases exist and are well-documented after the fact, and `docs/research/cryptography-audit-options.md` is a forward-looking milestone artifact for one specific case (professional audit prep) — but there is no standing, generalized policy statement (e.g., in `CONTRIBUTING.md` or a dedicated release-process doc) that every release/major feature/new-dependency addition triggers a security review pass as a matter of course, as opposed to being decided ad hoc per phase.
- **Desired State:** `07-milestones.md:5-9`: "Alterations to a code's function, large releases with new code, or the addition of new third party libraries are all mile markers to consider when planning major security improvements."

**GAP-023: `git-agentic.com`/website disclosure-policy mirroring unverifiable**
- **Category:** Implicit
- **Feature/Behavior:** Ch. 6's public-documentation-availability requirement: "documentation should be available at locations easily accessible to users such as on any relevant websites and project repositories."
- **Current State:** The repository references an external homepage (`git-agentic.com`, per the live GitHub API's `"homepage"` field) but that website's content is outside this repository and was not fetched/verified as part of this analysis.
- **Desired State:** `06-kb.md:7`: documentation "should be available at locations easily accessible to users such as on any relevant websites and project repositories." Marked Implicit / unverifiable-from-repo.

**GAP-024: Mailing-list / CVE subscription status for maintainers unverifiable**
- **Category:** Implicit
- **Feature/Behavior:** Ch. 5 self-check items on subscription to security mailing lists.
- **Current State:** No repository artifact (commit history, docs, CI config) can confirm or deny whether individual maintainers are personally subscribed to RustSec-announce, oss-security, Tauri's advisory feed, or GitHub's own advisory notifications for their account/org.
- **Desired State:** `05-up-to-date.md:9-10`. Marked Implicit / unverifiable-from-repo.

**GAP-025: Internal operational security of developer devices/infrastructure unverifiable**
- **Category:** Implicit
- **Feature/Behavior:** Ch. 4: "internal best practices on handling secrets, security of development devices and infrastructure."
- **Current State:** Nothing in the repository documents developer-machine hardening, 2FA enforcement on the GitHub org, CI runner trust boundaries beyond what GitHub Actions provides by default, or secrets-in-CI hygiene beyond `secrets.GITHUB_TOKEN` usage visible in `.github/workflows/audit.yml:38`.
- **Desired State:** `04-follow.md:11`. Marked Implicit / unverifiable-from-repo (this is inherently outside what a repo snapshot can prove).

**GAP-026: Legal/jurisdictional incident-reporting-law compliance unverifiable**
- **Category:** Implicit
- **Feature/Behavior:** Ch. 3: "Reporting any security incidents in the country the project team operates in, if required by law."
- **Current State:** No document addresses jurisdiction or legal reporting obligations; the project has no stated legal entity/jurisdiction anywhere in `README.md`, `LICENSE`, or `CONTRIBUTING.md` beyond the Apache-2.0 license text itself.
- **Desired State:** `03-response.md:23`. Marked Implicit — a one-or-few-maintainer OSS project may reasonably have no formal answer yet; this is a genuine silence, not a contradiction.

**GAP-027: CVE/security-announcement subscription for the desktop-app JS ecosystem is unaddressed by any tooling**
- **Category:** Partial
- **Feature/Behavior:** Ch. 5's "libraries, and dependencies related to your project, tools" scope, applied to `apps/desktop`'s npm stack (React, Vite, TypeScript, Tauri JS bindings, `@pierre/*`).
- **Current State:** The Rust side has a live, scheduled RustSec feed via `cargo-audit` (`.github/workflows/audit.yml:17-20,36`) providing genuine CVE-equivalent coverage for the Rust dependency tree. No equivalent mechanism (`npm audit`, `osv-scanner`, Snyk, or a dependabot npm ecosystem entry) exists for the npm tree, so half the project's dependency surface has the up-to-date-security practice and half does not.
- **Desired State:** `05-up-to-date.md:9-13`: "Are you subscribed to the security announcements mailing lists for all languages, libraries, and dependencies related to your project" and SAST-tooling self-check applying project-wide, not per-ecosystem.

**GAP-028: CodeQL coverage excludes the desktop-app frontend (TypeScript/JavaScript)**
- **Category:** Partial
- **Feature/Behavior:** Ch. 4's static-analysis-in-CI recommendation and Ch. 5's SAST self-check, applied project-wide.
- **Current State:** `.github/workflows/codeql.yml:22-29`'s matrix only analyzes `language: rust` and `language: actions` — it does not include a `javascript-typescript` entry, so `apps/desktop/src/` (React/TypeScript source) receives no CodeQL static analysis despite being a first-class part of the workspace (P35, `docs/adr/0045-native-desktop-read-model.md`).
- **Desired State:** `04-follow.md:9`: "integrating dependency checks and static analysis in CI, wherever possible" — "wherever possible" reasonably extends to every language actually shipped.

## Satisfied (current state meets or exceeds the desired state)

- **SECURITY.md exists with scope, reporting channel, and response timelines.**
  `SECURITY.md:31-55` provides an email + GitHub private-reporting channel, a
  report-content checklist, and concrete 3-day/7-day/90-day timelines — matching
  `02-pipeline.md:18-25`'s content list for channel, timeline, and report format
  (legal safe-harbor, bug-bounty-status, and reporter non-disclosure request are
  the listed items not yet covered; see GAP-015/GAP-017/GAP-018).
- **Private-reporting channel explicitly named, including GitHub's native
  mechanism.** `SECURITY.md:34-38` names both email and GitHub private
  vulnerability reporting, matching `02-pipeline.md:7-12`'s example list (modulo
  GAP-014's unverifiable enable-state).
- **No public-issue disclosure encouraged.** `SECURITY.md:33` and
  `CONTRIBUTING.md:65-66` both explicitly steer vulnerability reports away from
  public GitHub issues, consistent with `02-pipeline.md`'s intent.
- **Scheduled RustSec advisory scanning is live and current.**
  `.github/workflows/audit.yml` runs `rustsec/audit-check` daily via cron
  (`.github/workflows/audit.yml:17-20`) plus on every `Cargo.toml`/`Cargo.lock`
  change, and `git log` shows this is actively used and remediated — commit
  `d7106e5` "fix(audit): address RustSec issues #53–#68 (#70)" and `d3df9ce`
  demonstrate a live triage/fix loop, not a dormant workflow. This satisfies
  `05-up-to-date.md:26-27`'s "SAST tooling — Available free tooling" self-check
  for the Rust dependency surface.
- **CodeQL static analysis is enabled for Rust and GitHub Actions.**
  `.github/workflows/codeql.yml` runs on push/PR to `main` plus a weekly cron,
  satisfying `05-up-to-date.md:13`'s SAST-tooling recommendation (for the
  languages it covers — see GAP-028 for the gap in coverage).
- **Automated dependency updates are configured (cargo + GitHub Actions
  ecosystems).** `.github/dependabot.yml` schedules weekly cargo and
  github-actions update PRs, with deliberate, documented exceptions
  (`.github/dependabot.yml:11-29,35-40`) — satisfying
  `05-up-to-date.md:15,25`'s automated-update self-check for those two
  ecosystems (npm is the gap; see GAP-006/GAP-027).
- **CI enforces linting, formatting, and full test suite on every PR.**
  `.github/workflows/ci.yml:43-50` runs `cargo fmt --check`, `cargo clippy -D
  warnings`, `cargo test --workspace --all-targets`, and `cargo doc` on both
  Linux and macOS — a genuine CI-integrated testing practice per
  `04-follow.md:7`, even though the *review-before-merge enforcement* half of
  that same recommendation is not (GAP-009).
- **A living threat model documents deliberate security boundaries.**
  `docs/THREAT-MODEL.md` (326 lines) consolidates known cryptographic/protocol
  boundaries per feature (committed secrets, protected paths, TLS, signed
  commits, private branches), cross-referenced from `SECURITY.md:13-19` and
  `CONTRIBUTING.md:14-15` — this exceeds what the guide explicitly asks for and
  functions as strong supporting material for Ch. 6's documentation-currency
  goal (modulo the staleness noted in GAP-019) and for pre-audit readiness
  (Ch. 7).
- **Forward-looking audit-engagement research already exists.**
  `docs/research/cryptography-audit-options.md` (new, untracked at analysis
  time) is a concrete, actionable audit-firm shortlist, engagement-scope
  proposal, and pre-audit cleanup checklist — directly satisfying
  `07-milestones.md:11`'s "source a security audit... Audit Preparation
  checklist" recommendation and going beyond a bare self-check into an
  execution-ready plan.
- **Cryptography inventory exists implicitly and is well-documented.**
  `CLAUDE.md`'s "Stack & tooling" section and the `crypto`/`tlsio` crate
  quarantine rules, plus ADR-0008/0009/0010/0032/0042/0043, collectively answer
  `07-milestones.md:22-25`'s "Does your project use cryptography? How? Library
  or self-rolled?" self-check in detail: library-based (RustCrypto AEAD,
  X25519, Ed25519, rustls), never self-rolled primitives, explicitly quarantined
  by crate boundary and enforced socially per `CONTRIBUTING.md:39-45`.
- **Network exposure is documented per listener.** `docs/THREAT-MODEL.md` and
  ADR-0036/0040/0041/0042 describe `sc serve --http`'s exposure model (bearer
  tokens, TLS, connection/timeout caps, loopback-bind-by-default gate) in
  detail, substantially answering `07-milestones.md:27-28`'s "Does your project
  require internet access? How is it hosted?" self-check for the one listener
  surface the project ships.
- **License and contribution licensing terms are explicit.**
  `LICENSE` (Apache-2.0) and `CONTRIBUTING.md:68-71`'s explicit inbound-license
  statement satisfy general open-source-hygiene expectations the guide assumes
  as baseline (not a named self-check item, but consistent with the guide's
  overall transparency goal in Ch. 6).

## Areas Needing Separate Analysis

- **`08-what-next.md`** — referenced from the guide's README and every chapter
  footer, but absent from the cloned guide directory. Its content (likely
  covering what to do after completing the self-checks: audit engagement,
  community disclosure of the completed assessment) could not be compared.
  Re-run this analysis once the file is available.
- **GitHub org-level settings (2FA enforcement, SSO, team permissions,
  outside-collaborator audit)** — the `gh api repos/...` calls in this analysis
  are scoped to the repository, not the `git-agentic` organization; org-level
  security posture (Ch. 4's "operational security... infrastructure",
  Ch. 6's "list of access privileges") needs a separate, org-admin-scoped
  review.
- **`git-agentic.com` website content** — not fetched or verified; Ch. 2's
  `/.well-known/security.txt` mirroring recommendation and Ch. 6's public-
  documentation-availability requirement both depend partly on website content
  outside this repository's control.
- **`apps/desktop` frontend security practices in depth** — this analysis found
  gaps in *coverage* (CI, CodeQL, dependabot) for the npm/TypeScript surface
  but did not perform a feature-level security review of the Tauri IPC
  boundary, renderer capability restrictions, or the five typed repository
  commands referenced in `CLAUDE.md`'s P35 entry; that is a `structural-analyst`
  or dedicated frontend-security review task, not a gap-analysis-appropriate
  scope.

## Second-round delta (swarm-informed)

Second pass performed after adversarial-validator / evidence-based-investigator /
junior-developer / adversarial-security-analyst / devops-engineer swarm review of
the first-pass file. This section covers actor types the first pass under-weighted:
AI-agent contributors operating the repo, non-human principals (CI `GITHUB_TOKEN`
scopes, agent `gh` CLI write authority), external auditors, `sc serve` operators,
and downstream packagers. Every swarm claim below was independently re-verified
against the live repository and GitHub API before being folded in — none were
accepted on the swarm's assertion alone.

### Recategorizations

**GAP-009 — mechanism corrected, category unchanged (Partial), evidence rewritten.**
The original finding cited `gh api repos/git-agentic/src-control/branches/main/protection`
returning 404 as proof of "no branch protection." That endpoint only reports the
legacy branch-protection API; the repository in fact uses the newer **rulesets**
API. Re-verified: `gh api repos/git-agentic/src-control/rulesets` returns one
active ruleset (`id 18739705`, `name: "main"`, `enforcement: "active"`,
`bypass_actors: []`, `current_user_can_bypass: "never"`). Its `rules` array
contains `deletion`, `non_fast_forward`, and a `pull_request` rule — so direct
pushes, force-pushes, and branch deletion on `main` ARE actively blocked, and a
PR IS technically required to land any change. This is stronger than the original
finding stated. However, the `pull_request` rule's own parameters show
`"required_approving_review_count": 0` and there is no `required_status_checks`
rule type anywhere in the ruleset — so a PR can be merged with zero approvals and
with red CI (fmt/clippy/test failing) and still land, which is the gap that
survives. Corrected finding: **PR-routing is enforced; review-approval and
CI-gating are not.** Category stays **Partial** (enforcement exists but is
incomplete against `04-follow.md:8`'s "requiring code reviews before merging"),
not Missing as a naive reading of the 404 would have implied, and not fully
resolved either. Nuance carried into GAP-032 below: a solo/near-solo maintainer
literally cannot self-approve their own PR under GitHub's rules, so setting
`required_approving_review_count > 0` alone does not close this without also
adding a second reviewing principal (human or otherwise) — see GAP-032.

**GAP-014 — upgraded from Missing to Divergent; corrected with conclusive
evidence.** The original finding treated the "is private vulnerability reporting
actually enabled" question as unverifiable from available API scope and
classified it Missing on the strength of `SECURITY.md`'s own text. Re-verified
directly: `gh api repos/git-agentic/src-control/private-vulnerability-reporting`
returns `{"enabled":false}` — conclusive, not inferred. This changes the shape
of the finding: `SECURITY.md:34-38` does not merely omit a recommended channel
(Missing), it **actively directs reporters to a specific named channel
("GitHub's private vulnerability reporting... on this repository") that does not
function** — a report submitted that way is not deliverable through the
mechanism SECURITY.md describes. That is a contradiction between the documented
process and the actual repository configuration, which is the Divergent
definition ("both states address the same concern, but in incompatible ways").
Recategorized **Missing → Divergent**. The "Satisfied" list entry "Private-
reporting channel explicitly named, including GitHub's native mechanism" is
corrected: only the email channel in `SECURITY.md:36` is currently live; the
GitHub-native half of that same bullet is non-functional and should not have
been credited as satisfied.

**GAP-003 — evidence line corrected, finding stands.** The original evidence
claimed `grep -rn -i "reproducible"` returns "zero matches" repo-wide. Re-run:
it actually returns three hits outside this audit file itself —
`crates/repo/src/ws.rs:1313` ("never bit-for-bit reproducible by re-encrypting
the same..." — about ciphertext non-determinism, unrelated to build
reproducibility), `apps/desktop/README.md:67` ("reproducible without embedding"
— about a UI/state property, unrelated to build reproducibility), and
`docs/superpowers/specs/2026-06-24-phase2-committed-secrets-design.md:137`
("reproducible" test determinism, unrelated to build reproducibility). None of
the three concern build/compilation reproducibility, so the underlying gap is
unchanged — but the "zero matches" claim was imprecise and is corrected here.
Additionally: mark GAP-003, and the packager-facing readings of GAP-005 (SBOM)
and GAP-020 (third-party library list), as **premature-until-distribution**.
`Cargo.toml:26` sets `publish = false` workspace-wide with the comment
"nothing publishes to crates.io by accident," and no release/packaging workflow
exists anywhere in `.github/workflows/`. Reproducible builds, SBOM generation,
and a curated third-party-library list all exist principally to let a
*downstream consumer* verify what they're receiving — with zero distribution
channels shipped yet, there is no such consumer today. The gaps remain valid
(the guide's self-checks are still unaddressed, and all three become load-
bearing the moment a release workflow ships) but their priority should be read
as tied to the (currently absent) distribution milestone, not as an immediate
operational risk.

**GAP-006 / GAP-020 — evidence corrected, categories unchanged.** The original
GAP-020 text described the npm dependency surface as living "only implicitly in
`Cargo.lock`... and `apps/desktop/package.json`," which by omission understated
what's committed. Re-verified: `apps/desktop/package-lock.json` **is** committed
(`lockfileVersion: 3`, ~234 resolved packages, per-package `sha512` integrity
hashes). This does not close GAP-006 or GAP-020 — it sharpens them: the lockfile
exists and could enforce integrity, but `grep -n "npm" .github/workflows/*.yml`
confirms (again) that no workflow ever runs `npm ci` (or any npm command), so
the committed integrity hashes are never actually checked against installed
packages in CI. The gap is not "no lockfile" (false) but "a lockfile exists and
is never verified" (true, and arguably a sharper finding than the original).

**GAP-012 — scope widened in place, no new ID (fold decision).** Swarm item E
("access-privilege inventory omits non-human principals") is folded into
GAP-012 rather than minted as a new gap: it is the same missing artifact (a
documented list of access privileges), just missing a category of principal the
first pass didn't consider. Decision recorded here rather than as GAP-035 to
avoid double-counting the same absent document under two IDs. Widened scope
now on record: GAP-012 covers not only human GitHub-org/npm/DNS/signing-key
access but also **non-human principals** — the CI `GITHUB_TOKEN`'s granted
scopes per workflow (`.github/workflows/audit.yml:23-28` grants
`contents: read, checks: write, issues: write`; `.github/workflows/codeql.yml:11,18-21`
grants `contents: read` repo-wide plus `security-events: write, actions: read,
contents: read` in the analyze job), and any AI-agent principal operating under
`docs/agents/issue-tracker.md`'s `gh` CLI conventions (create/comment/label/close
issues and PRs) — none of which appear in any access-privilege inventory because
no such inventory exists at all yet.

### Withdrawals

None. All 28 first-pass findings were re-examined against the swarm's claims and
survive: GAP-009 and GAP-014 are recategorized (not withdrawn — the underlying
gaps still exist, just characterized more precisely); GAP-003/005/020 gain a
distribution-timing caveat but remain open findings; GAP-006/020 gain corrected
evidence but the same conclusion. No first-pass finding was found to be false
positive.

### New findings

**GAP-029: Third-party GitHub Actions pinned by mutable tag, not commit SHA**
- **Category:** Missing
- **Feature/Behavior:** Ch. 4's development/build/CI best-practices scope (`04-follow.md:7-9`) and the OpenSSF Scorecard self-check already flagged in GAP-004 — Scorecard's "Pinned-Dependencies" check specifically requires GitHub Actions to be pinned to a full commit SHA, not a mutable tag, to prevent a compromised upstream action from silently injecting code into CI.
- **Current State:** Every third-party action reference across all three workflows uses a mutable tag: `.github/workflows/ci.yml:24` (`actions/checkout@v7`), `:39` (`dtolnay/rust-toolchain@1.96.1`), `:42` (`Swatinem/rust-cache@v2`); `.github/workflows/codeql.yml:31` (`actions/checkout@v7`), `:32` (`github/codeql-action/init@v3`), `:42` (`github/codeql-action/analyze@v3`); `.github/workflows/audit.yml:35` (`actions/checkout@v7`), `:36` (`rustsec/audit-check@v2`). None use a 40-character commit SHA. This was independently proposed by two different augmenters in the swarm, so it was checked first and hardest — confirmed by direct grep of `uses:` lines in all three workflow files, no exceptions found.
- **Desired State:** `04-follow.md:9`: "integrating dependency checks and static analysis in CI, wherever possible," read alongside the OpenSSF Scorecard reference at `04-follow.md:25` this project has not yet run (GAP-004) — Scorecard's Pinned-Dependencies check treats floating-tag Action pins as a specific, named finding.

**GAP-030: Incident-response scope omits compromised/prompt-injected AI-agent principals**
- **Category:** Missing
- **Feature/Behavior:** Sibling of GAP-011 (no documented security-incident process at all). Sharpened here because the guide's incident-type list (`03-response.md:18-23`: "supply-chain attacks, malware campaigns... infection or other attacks on the project's development or production systems, and data breaches") was written for human-operated projects and does not anticipate — and this repository's own incident process (which doesn't exist; see GAP-011) therefore also does not address — a distinct incident class this project is unusually exposed to: a compromised or prompt-injected AI-agent principal acting with the write authority `docs/agents/issue-tracker.md` and `CLAUDE.md`'s "Agent skills" section (`CLAUDE.md:237-258`) grant (issue/PR creation, labeling, closing, and — per `docs/agents/issue-tracker.md:7-12` — commenting and editing via `gh`).
- **Current State:** `docs/agents/issue-tracker.md`, `docs/agents/triage-labels.md`, `docs/agents/domain.md`, `AGENTS.md`, and `CLAUDE.md`'s "Agent skills" section collectively document how agents operate the repository's issue tracker and (per `ROADMAP.md`'s phase log and `docs/superpowers/plans/`) drive substantial engineering work, but no document anywhere addresses what happens if an agent's instructions are compromised (prompt injection via a malicious issue body, a poisoned dependency's doc comments, or a compromised upstream skill) and it takes a harmful repository action. GAP-011 already establishes no incident-response process exists at all; this finding specifically notes the incident-type taxonomy the project would need to write already has a gap even in the abstract, since neither the guide nor any project document contemplates this actor class.
- **Desired State:** `03-response.md:18-23` — the incident-type list this project would need to extend, not just adopt verbatim.

**GAP-031: No documented boundary keeping private security reports out of the automated/public agent triage pipeline**
- **Category:** Implicit
- **Feature/Behavior:** Sharpens GAP-010 (no internal vulnerability-response documentation). The specific sharpening: this repository already runs agents over its *public* issue tracker by design (`docs/agents/issue-tracker.md`, `docs/agents/triage-labels.md`'s `needs-triage`/`ready-for-agent` labels), and `.github/workflows/audit.yml:26-28` grants the workflow `issues: write` specifically to auto-file RustSec findings as issues (per the workflow's own comment: "Scheduled runs file findings as GitHub issues"). No document states a boundary such as "a report received via the private channel in SECURITY.md must never be filed, labeled, or processed through the public agent-triage pipeline" or "an agent triaging public issues must recognize and never act on content resembling an undisclosed vulnerability."
- **Current State:** Checked `SECURITY.md`, `CONTRIBUTING.md`, `docs/agents/*`, and `CLAUDE.md` for any such boundary statement — none exists in either direction (no explicit boundary, but also no evidence any leak has occurred; this is a genuine silence on a real adjacency, not a demonstrated incident). Classified **Implicit** rather than Missing because the guide itself never explicitly asks for this specific boundary — it is a risk that emerges from combining two things the guide does ask for (Ch. 2's private channel, Ch. 3's internal process) with an actor type (autonomous agent triage) the guide doesn't contemplate, so the "gap" is genuinely in the silence between the two chapters as applied to this project's actual operating model, not a direct unmet checklist item.
- **Desired State:** `03-response.md:7-10` (internal handling process, responsible-member assignment) and `02-pipeline.md:16` ("Who handles your pipeline and relevant reports is also important... you may want access to the project's security reporting system to only be available to the software maintainers"), read together against this project's public-agent-triage operating model.

**GAP-032: No human-in-the-loop requirement for code-review approval**
- **Category:** Missing
- **Feature/Behavior:** Sharpens GAP-009. `04-follow.md:8`'s "requiring code reviews before merging" self-check is satisfiable, as configured, by any principal with write access approving — GitHub's ruleset `pull_request` rule (verified in the GAP-009 recategorization above) restricts *whether* review is required (currently: not required at all, `required_approving_review_count: 0`) but not *who* may provide it. Nothing in the ruleset, `CONTRIBUTING.md`, or any other document requires that the approving reviewer be a human, or be a principal distinct from whatever agent (if any) authored the change.
- **Current State:** `gh api repos/git-agentic/src-control/rulesets/18739705`'s `pull_request` rule object has no `required_reviewers` team/principal restriction (`"required_reviewers": []`) and no code-owner requirement (`"require_code_owner_review": false`). `CONTRIBUTING.md` describes the CI bar (fmt/clippy/test/doc) and PR-based workflow but never states who — human or agent — must review a change, or that agent-authored changes need a human reviewer distinct from the agent.
- **Desired State:** `04-follow.md:8`. The guide's underlying intent (an independent second set of eyes catching what the author missed) implicitly assumes the reviewer is a different *kind* of principal with different failure modes than the author — an assumption this project's all-agent-capable contribution model doesn't yet guarantee.

**GAP-033: Vendored hand-patched dependency has no provenance record outside a code comment, and would misrepresent an SBOM/library inventory if produced today**
- **Category:** Partial
- **Feature/Behavior:** Sharpens GAP-005 (no SBOM) and GAP-020 (no third-party library list). `Cargo.toml:9-10` carries `[patch.crates-io] glib = { path = "vendor/glib-0.18.5-patched" }` — a hand-patched fork of the upstream `glib` crate, vendored in-tree specifically to carry a fix for **RUSTSEC-2024-0429** ahead of upstream (per the `.github/workflows/audit.yml:44-45` comment: "glib 0.18.5 is patched in-tree for RUSTSEC-2024-0429; cargo-audit matches versions only, so remove this exception with that patch"). `audit.yml:48`'s ignore list force-suppresses `RUSTSEC-2024-0429` for this reason.
- **Current State:** The only record of this patch's existence, rationale, and removal condition is a workflow YAML comment (`audit.yml:39-45`) and the vendored source tree itself (`vendor/glib-0.18.5-patched/PROVENANCE.md` exists inside the vendor directory per the earlier `git show` of commit `d7106e5`'s file list, but is not referenced from any top-level security or dependency document). A version-keyed dependency list or SBOM generated mechanically from `Cargo.lock` today (`Cargo.lock` records `glib 0.18.5` with no marker distinguishing the patched vendor copy from the unpatched upstream crate of the same version) **would misrepresent** this dependency as unpatched upstream `glib 0.18.5`, silently reintroducing the appearance of an unfixed RUSTSEC-2024-0429 exposure to anyone reading the SBOM without also reading the audit workflow's suppression comment.
- **Desired State:** `06-kb.md:9,15-16`: "Creating a Statement Bill of Materials... Being transparent about your organization's supply chain provides context for users to make educated decisions" and self-check "List of third party libraries in project... Create SBOM (if relevant)." An accurate SBOM/library list needs to be capable of representing a vendored, hand-patched fork distinctly from its unpatched upstream namesake — a capability that doesn't exist today because no SBOM/library-list artifact exists at all (GAP-005/GAP-020), and the current sole provenance record (a workflow comment) would not survive being mechanically summarized into one.

**GAP-034: No operator-facing hardening/incident runbook for `sc serve` deployments** *(low confidence — included per swarm request; borderline in-scope for a guide written for library/application maintainers rather than deployed-service operators)*
- **Category:** Partial
- **Feature/Behavior:** `04-follow.md:11`'s "security of development devices and infrastructure" and `07-milestones.md:27-28`'s exposure self-check ("Does your project require internet access? How is it hosted?"), read against the specific fact that this project ships a listener an end operator runs themselves (`sc serve --http`/`--stdio`), rather than only being a library or CLI consumed locally.
- **Current State:** ADR-0036 (HTTP transport), ADR-0040 (access control: bearer tokens, `--read-only`, fail-closed non-loopback bind gate), ADR-0041 (listener resource limits), and ADR-0042 (in-binary TLS) thoroughly document the *mechanisms* available to an operator (what flags exist, what they do, what the fail-closed defaults are) and `docs/THREAT-MODEL.md` documents the *boundaries* (e.g. plaintext-by-default without `sc+https://`). None of these is a task-oriented runbook a first-time operator would follow ("here is how to stand up `sc serve` safely for a given trust level," "here is what to do if you suspect your listener was scanned/attacked," "here is the minimum flag set for a public bind"). `ROADMAP.md`'s Deferred section (lines ~685-697) further documents known operational gaps in the listener itself (no connection pool cap, no idle-transfer watchdog, no accept-loop backoff) without pairing them with interim operator mitigations.
- **Desired State:** `04-follow.md:11`, `07-milestones.md:27-28`. Flagged low-confidence because the guide is framed throughout around a *project's own* development/build/hosting practices, not around documentation for *third-party operators* of a tool the project ships — whether this counts as an OSTIF-guide gap versus ordinary product documentation is a judgment call this analysis resolves toward inclusion (the exposure self-check is explicit and the project does host a listener) but flags for the reader to weigh.

### Updated counts (first-pass + delta)

The second-round delta adds 6 new findings (GAP-029–034) to the original 28,
recategorizes 2 (GAP-009 stays Partial with corrected evidence; GAP-014 moves
Missing → Divergent), corrects evidence on 3 more without changing category
(GAP-003, GAP-006, GAP-020), folds 1 swarm item into an existing gap
(non-human principals → GAP-012, no new ID), and withdraws none.

| Category | First-pass count | Delta | New total |
|----------|------------------:|------:|----------:|
| Missing | 15 | −1 (GAP-014 out) +3 (GAP-029, 030, 032) | 17 |
| Partial | 8 | +2 (GAP-033, 034) | 10 |
| Divergent | 1 | +1 (GAP-014 in) | 2 |
| Implicit | 4 | +1 (GAP-031) | 5 |
| **Total** | **28** | **+6** | **34** |

## Third-round delta: live code-scanning evidence (2026-07-18, user-requested)

After the report was rendered, the user asked for the repository's live code-scanning
surface (`https://github.com/git-agentic/src-control/security/code-scanning`) to be
checked and folded in. Queried via `gh api repos/git-agentic/src-control/code-scanning/
{alerts,analyses}`. Meanwhile the remote moved past the audit's evidence snapshot
(`d7106e5` → `d6e60ac`): four commits landed on main the same morning —
`e570b8f` "Add scorecard_analysis workflow configuration (#74)", `d6e60ac`
"fix(ci): restore Scorecard workflow (#75)", `8b09a95` "bump github/codeql-action
from 3 to 4 (#72)", `0f3ab3f` dependabot cargo-minor-patch group (#73).

### State of the code-scanning surface (verified live)

- **17 open alerts, all from tool `Scorecard`** (numbers 4–20), uploaded
  2026-07-18T08:29:36Z from the new `scorecard_analysis.yml` run on `d6e60ac`.
- **Zero open CodeQL alerts.** Alerts 1–3 are historical CodeQL
  `rust/access-invalid-pointer` findings that are no longer open.
- **CodeQL analyses on `main` remain `/language:rust` and `/language:actions`
  only** — no `javascript-typescript` category. GAP-028 unchanged.
- The new `scorecard_analysis.yml` is itself exemplary: every action SHA-pinned
  with version comments (`actions/checkout@9c091bb2… # v7.0.0`,
  `ossf/scorecard-action@4eaacf05… # v2.4.3`, `github/codeql-action/upload-sarif@8aad20d1… # v4.36.2`),
  top-level `permissions: read-all`, job-scoped `security-events: write` +
  `id-token: write`, `persist-credentials: false`, weekly cron + push,
  `publish_results: true`. Scorecard raised no Pinned-Dependencies or
  Token-Permissions alert against it — it is the in-repo template for GAP-029.

### Recategorization

**GAP-004 — Missing → Partial.** OpenSSF Scorecard now runs (workflow added in
#74/#75, post-dating the first-pass evidence; weekly + on push; SARIF uploaded to
code scanning; `publish_results: true`). What remains open: the 17 findings it
produced are untriaged; the OpenSSF best-practices badge is unaddressed
(`CIIBestPracticesID` score 0 — a named Scorecard check, folded here rather than
minted as a new gap); and the OWASP ASVS half of the original self-check remains
unconsidered (still judged largely N/A for a CLI/VCS). `MaintainedID` score 0 is
informational only ("repository created within the last 90 days") and not
actionable.

### Live corroborations of existing findings (no category changes)

- **GAP-029** — corroborated by the tool itself: 8 open `PinnedDependenciesID`
  alerts at exactly the predicted locations (`ci.yml:24,39,42`,
  `codeql.yml:31,32,42`, `audit.yml:35,36`). Evidence refresh: #72 bumped
  `github/codeql-action` v3 → v4 — still a mutable tag; the gap stands at the
  same lines.
- **GAP-009 / GAP-032** — corroborated: `CodeReviewID` score 0 ("Found 0/26
  approved changesets") and `BranchProtectionID` score 3 ("branch 'main' does
  not require approvers… no status checks found to merge onto branch 'main'…
  codeowners review is not required").
- **GAP-025** — corroborated: `TokenPermissionsID` (high) on `audit.yml:25`,
  "topLevel 'checks' permission set to 'write'" — the exact nit the
  devops-engineer flagged pre-Scorecard.
- **GAP-001 / GAP-002** — corroborated: `FuzzingID` score 0 ("no fuzzer
  integrations found").
- **GAP-033 — the predicted misrepresentation demonstrably occurred.**
  `VulnerabilitiesID` (high, score 0) lists "Project is vulnerable to:
  RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g" — Scorecard's OSV check read
  `Cargo.lock`'s `glib 0.18.5` and flagged it as an existing vulnerability,
  exactly the false-positive GAP-033 predicted a version-keyed consumer would
  produce for the patched vendored copy.
- Positive signals for the Satisfied list: `CITestsID` 9/10 (25 of 26 merged
  PRs CI-checked) and `SASTID` 9/10 (22 of 26 commits SAST-checked).

### New finding

**GAP-035: Accepted-advisory ignore list omits one member of its own accepted
family (RUSTSEC-2024-0413/`atk`), surfaced by independent-scanner disagreement**
- **Category:** Partial
- **Feature/Behavior:** Ch. 5's up-to-date-security posture (`05-up-to-date.md:9-13`)
  and Ch. 6's documentation-currency requirement, applied to the advisory-
  acceptance record: every accepted advisory should be deliberately listed with
  its removal gate, and independent scanners should agree with the documented
  posture.
- **Current State:** Scorecard's `VulnerabilitiesID` alert (#18) lists 18
  advisories; the `audit.yml` `ignore:` list documents 17. Set-difference:
  **RUSTSEC-2024-0413** (`atk` 0.18.2 — "gtk-rs GTK3 bindings - no longer
  maintained", confirmed via OSV API and present in `Cargo.lock`). It is the
  same GTK3-unmaintained family as nine already-ignored siblings
  (RUSTSEC-2024-0411/0412/0414–0420) whose removal gate ("remove… when Tauri 3
  moves the stack to GTK4") is documented in `audit.yml:39-45` — this member
  was simply omitted. The daily `cargo-audit` run does not fail on it because
  unmaintained-class advisories warn rather than error, so the omission was
  invisible until a second scanner (Scorecard/OSV) counted it. Not a new
  vulnerability — an accepted-risk record that is incomplete, now flagged
  divergently by two tools.
- **Desired State:** `05-up-to-date.md:9-13` (staying current with advisories);
  `06-kb.md:7` (documentation that is current). Remediation: add
  RUSTSEC-2024-0413 to the `ignore:` list under the existing GTK3 removal-gate
  comment (or restructure the acceptance record per GAP-033's provenance work),
  keeping cargo-audit and Scorecard tellings consistent.

### Updated counts (all three rounds)

| Category | Second-round total | Third-round delta | New total |
|----------|-------------------:|------:|----------:|
| Missing | 17 | −1 (GAP-004 out) | 16 |
| Partial | 10 | +1 (GAP-004 in) +1 (GAP-035) | 12 |
| Divergent | 2 | — | 2 |
| Implicit | 5 | — | 5 |
| **Total** | **34** | **+1** | **35** |
