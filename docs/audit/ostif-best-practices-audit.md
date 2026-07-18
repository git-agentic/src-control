---
title: "Gap Analysis: src-control vs OSTIF Security Best Practices Guide"
comparison_direction: "src-control repository (current state) -> OSTIF/Least Authority Security Best Practices Guide (desired state)"
scope: "The whole repository (code, CI, docs, GitHub configuration via live API) compared against all six OSTIF practice areas; the guide's missing 08-what-next.md chapter and the external git-agentic.com website were excluded."
generated: "2026-07-18"
updated: "2026-07-18 — fourth round: Now + Soon tiers remediated (PRs #76–#87); code-scanning down from 17 open alerts to 3, all tracing to one deferred item (required human approvals) plus an optional badge"
generated_by: "han:gap-analysis"
sections_included:
  - executive_summary
  - indexed_gaps
  - technical_details
  - swarm_findings
  - actionable_todos
---

# Gap Analysis: src-control vs OSTIF Security Best Practices Guide

## How to Read This Report

This report compares **the src-control repository** (what exists today) against **the OSTIF Security Best Practices Guide** (what is expected). It is layered, so you can stop at any section and still have a complete picture at that level of detail:

- **Section 0 — Remediation Status.** What has been fixed since the audit ran. Read this first if you want the current state rather than the original findings.
- **Section 1 — Executive Summary.** The shape and magnitude of the gap in plain language, *as first audited*. Read this if you have two minutes.
- **Section 2 — Indexed Gaps.** Every gap, individually titled and explained in plain language, with a stable ID (e.g., `G-007`) you can cite in tickets, threads, and follow-up work.
- **Section 3 — Technical Details.** Engineering-grade fidelity for each gap: where it lives, what would need to change, and how to act on it.
- **Section 4 — Swarm Findings.** Confidence signals, contradictions, and augmentations from a panel of five secondary analyses. Read this to know which gaps are most certain.
- **Section 5 — Actionable TODO List.** The prioritized work plan (T-1 … T-26) mapping every gap to a concrete action, effort estimate, and tier. **Now and Soon tiers are done (see Section 0); the Deferred tier remains.**

Every gap has a stable ID. Sections 3–5 reference those IDs. The full evidence trail (verbatim analyzer findings, GAP-NNN ↔ G-NNN maps 1:1) is in `docs/audit/gap-analysis-source.md`.

**Gap categories used throughout:**
- **Missing** — the guide expects it; the repository does not have it.
- **Partial** — present in both, but the repository does not fully satisfy the guide.
- **Divergent** — present in both, but the repository does something materially different (or contradictory).
- **Implicit** — assumed or implied by the guide but not directly checkable from the repository; needs a decision or an out-of-repo check.

---

## 0. Remediation Status (as of 2026-07-18)

> This section was added after the gap analysis was acted on. Sections 1–5 below describe the repository **as first audited**; this section records what has since been fixed. Where they differ, this section is current.

**Both actionable tiers of the work plan are done.** The Now tier (T-1…T-9, T-26) and the Soon tier (T-10…T-21) all shipped across pull requests #76–#87, plus repository-settings changes and an organization-wide two-factor-authentication requirement. Only the **Deferred tier (T-22…T-25)** remains — OSS-Fuzz enrollment, reproducible builds, a release pipeline with supply-chain attestations, and a hardening guide for people who run the server component — and every one of those is deliberately parked behind a trigger that hasn't happened yet: the project still distributes nothing for a consumer to verify.

**The independent security scorecard tells the story in numbers: 17 open findings became 3.**

| Scorecard finding (first run) | Now/Soon fix | Status |
|---|---|---|
| 8 × building-blocks-not-pinned-by-fingerprint | T-2 (SHA-pinning) | ✅ auto-closed |
| Automation token over-permissioned | T-20 (job-scoped token) | ✅ auto-closed |
| Not fuzzed | T-13 (nightly fuzzer) | ✅ auto-closed |
| Static-analysis / CI-test coverage | T-3, T-4 | ✅ improved to passing |
| Dependency reported vulnerable (the patched-component trap) | G-033 annotation + rationale | ✅ dismissed with documented reason |
| Repository younger than 90 days (informational) | — | ✅ dismissed (self-resolves with age) |

The **automated code analysis is fully clean** — zero open findings — and now covers the desktop application's language as well as the core (T-3).

**The 3 remaining findings are not new gaps and not oversights — they are one already-tracked deferred item plus one optional extra:**

- **Two findings (required review approvals, and branch-protection completeness) share a single root cause: review approvals are set to zero.** This is gap G-032 / todo T-16 in the plan, and it is deliberately held: under the hosting platform's rules a lone maintainer cannot approve their own change, so requiring approvals needs a second reviewer to exist first. Note the branch-protection finding already *improved* once merge-gating on passing checks landed (T-9); the rest of it unlocks together the day a second reviewer is added and approvals can be required.
- **One finding is an optional best-practices badge**, now showing "in progress." Completing it is nice-to-have, not a gap the guide requires.

**Two closing items still need a human and cannot be done from the repository:** deploying the machine-readable security-contact file to the project website (`/.well-known/security.txt`), and the maintainer personally confirming the security-feed subscriptions the documentation now lists. Both are noted in Section 5.

---

## 1. Executive Summary

> **Historical.** The summary below describes the repository as first audited, before any remediation. See Section 0 for current status.

**Bottom line:** The project is substantially ahead of the guide in the areas it has invested in deliberately — a detailed living threat model, daily automated vulnerability scanning of its core dependencies, automated code analysis of its core language, and an already-drafted plan for a professional audit. But the audit found **35 gaps**, and they cluster in places the project has not yet looked: platform-level protections that are switched off, a security policy document that has drifted out of date and points reporters at a channel that does not work, a desktop application that sits entirely outside every automated safety net, and internal security processes that exist as habit but not as written policy.

**Same-day update:** the security scorecard the audit recommended (G-004) was added and run before this report was even finished — it now runs weekly, and its first run independently confirmed five of this report's findings at the exact predicted locations, demonstrated the bundled-component misrepresentation trap (G-033) live, and surfaced one new discrepancy (G-035). Its 17 open findings then dropped to 3 as remediation shipped — see **Section 0** for current status.

**Magnitude at a glance:**

| Category    | Count | Plain-language meaning                                                  |
|-------------|-------|-------------------------------------------------------------------------|
| Missing     | 16    | Things the guide expects that are not present today.                    |
| Partial     | 12    | Things that exist but do not fully meet expectations.                   |
| Divergent   | 2     | Things that exist but behave differently than documented or expected.   |
| Implicit    | 5     | Expectations that cannot be verified from the repository and need a decision. |
| **Total**   | **35** |                                                                        |

**The shape of the gap (five themes):**

- **The hosting platform's built-in protections are mostly off.** Secret leak scanning, automatic security-fix suggestions, the private vulnerability-reporting channel, required review approvals, and merge gating on passing checks are all disabled or unconfigured — each one is a switch or a small settings change, verified directly against the live platform.
- **The public security policy is stale and partly broken.** The document reporters and users read to understand the project's guarantees describes an older version of the encryption design, and it directs vulnerability reporters to a named private channel that is confirmed to be switched off — a report sent that way is undeliverable today.
- **The desktop application is invisible to every safety net.** The automated testing, dependency scanning, vulnerability alerting, and code analysis that protect the core system do not cover the desktop app's separate technology ecosystem at all — that half of the project ships with no automated checks whatsoever.
- **Security process lives in practice, not on paper.** There is no written internal procedure for handling a vulnerability report, no incident-response plan, no inventory of who (and what) holds which access, and no standing rule for when a release or new dependency triggers a security review.
- **The project's unusual operating model creates gaps the guide cannot see.** This repository is heavily operated by AI agents. The guide assumes human teams, so nothing addresses a compromised or manipulated agent as an incident type, nothing prevents an agent from approving another agent's change, and nothing keeps privately reported vulnerabilities out of the automated public triage pipeline.

**What this means for the work ahead:** The good news is that most of the highest-confidence gaps are cheap: roughly a third of the entire list closes with platform toggles, one-line configuration additions, and a single revision of the security policy document. A second tranche is documentation work — writing down processes and inventories that mostly already exist as practice. Only a few items (fuzz testing infrastructure, reproducible builds, a release pipeline with supply-chain attestations) are genuinely large, and several of those are deliberately deferred because the project does not yet distribute anything for a consumer to verify. The work plan in Section 5 sequences all of this.

**What is already in good shape** (so this report is fair): the security policy document exists with a working email channel, report-format guidance, and concrete response timelines; core-language dependency scanning runs daily and is demonstrably acted on; automated code analysis covers the core language **with zero open findings** (three historical memory-safety findings were fixed); the new weekly scorecard confirms nearly all merged changes are CI-checked and analysis-checked; scheduled dependency-update proposals are configured for two of the three ecosystems; formatting, linting, and the full test suite run on every proposed change; a thorough threat model and a professional-audit preparation plan already exist; and the cryptography is library-based, never self-rolled, and architecturally quarantined. Two earlier credits were corrected during validation: the platform-native private reporting channel named in the policy is in fact disabled (only email works), and the test suite *runs* on every change but a failing run does not technically block a merge.

**Where to look next:** Section 2 lists every gap individually. Section 3 has the technical detail engineers need. Section 4 reports how confident the analysis is and where secondary checks disagreed. Section 5 is the prioritized todo list.

---

## 2. Indexed Gaps

**Index (scan view):**

| ID    | Category  | Title (plain language)                                                        |
|-------|-----------|-------------------------------------------------------------------------------|
| G-001 | Missing   | No fuzz or property-based testing of untrusted-input handling                  |
| G-002 | Missing   | Not enrolled in the free continuous-fuzzing service                            |
| G-003 | Missing   | No reproducible-build capability                                               |
| G-004 | Partial   | Security scorecard now runs (added same-day); findings untriaged, standards review open² |
| G-005 | Missing   | No software bill of materials                                                  |
| G-006 | Missing   | Desktop app's dependencies are never checked or tested by automation           |
| G-007 | Missing   | Platform secret-leak scanning and push protection are switched off             |
| G-008 | Missing   | Automatic security-fix proposals are switched off                              |
| G-009 | Partial   | Changes must go through a proposal, but approval and passing checks are not required |
| G-010 | Missing   | No written internal procedure for handling a vulnerability report              |
| G-011 | Missing   | No written security-incident response plan                                     |
| G-012 | Missing   | No inventory of who and what holds which access                                |
| G-013 | Missing   | No record of security-announcement subscriptions                               |
| G-014 | Divergent | The security policy names a private reporting channel that is switched off     |
| G-015 | Partial   | No legal safe-harbor statement for good-faith researchers                      |
| G-016 | Missing   | No machine-readable security contact file for the website                      |
| G-017 | Partial   | No statement on whether a bug bounty exists                                    |
| G-018 | Partial   | Reporters are never asked to hold findings in confidence                       |
| G-019 | Divergent | The security policy describes an outdated version of the product               |
| G-020 | Partial   | No readable inventory of third-party components                                |
| G-021 | Missing   | No statement about sensitive data and the impossibility of true deletion       |
| G-022 | Partial   | No standing rule for when releases or new dependencies trigger security review |
| G-023 | Implicit  | Whether the website mirrors the disclosure policy is unverified                |
| G-024 | Implicit  | Whether maintainers are actually subscribed to security feeds is unverifiable  |
| G-025 | Implicit  | Developer-device and infrastructure hygiene is largely unverifiable            |
| G-026 | Implicit  | Legal reporting obligations are unaddressed                                    |
| G-027 | Partial   | Half the project's dependencies have no vulnerability feed at all              |
| G-028 | Partial   | Automated code analysis skips the desktop app's language                       |
| G-029 | Missing   | Automation building blocks are referenced by movable labels, not fingerprints¹ |
| G-030 | Missing   | Incident planning ignores the compromised-AI-agent scenario¹                   |
| G-031 | Implicit  | Nothing keeps private reports out of the automated public triage pipeline¹     |
| G-032 | Missing   | Nothing requires a human in the review loop¹                                   |
| G-033 | Partial   | A hand-patched bundled component has no visible provenance record¹             |
| G-034 | Partial   | No hardening guide for people who run the server component¹                    |
| G-035 | Partial   | The accepted-advisory list omits one member of its own accepted family²        |

¹ *Surfaced by the validation swarm (G-029 independently by both the security and operations augmenters; G-030/031/032/034 by the actor-perspective sweep; G-033 jointly by the actor sweep and the security augmenter) and confirmed by the analyzer's second pass.*
² *Updated/added in the third evidence round (2026-07-18): the live code-scanning surface was checked at the user's request after the scorecard workflow landed on the same day.*

> IDs are stable for the life of this report. Cite them as `G-NNN` in tickets and follow-up work.

---

### G-001 — No fuzz or property-based testing of untrusted-input handling
- **Category:** Missing
- **Expected:** A wide testing range including fuzzing (feeding random malformed input to find crashes) and property-based testing.
- **Current:** Only conventional example-based tests run, locally and in automation.
- **Why it matters:** The project ships a network server that parses data sent by strangers. A crash or memory blow-up on malformed input is a way for an attacker to knock the server over remotely.
- **Additional context (swarm):** This is not aspirational here — the project's own design records already name a residual weakness in exactly the input-parsing path a fuzzer would exercise, so there is a concrete, pre-motivated first target. The property-testing half is nearly free with existing tooling; the fuzzing half needs one new scheduled job. *(Third round: the live scorecard independently scored fuzzing 0/10 — "no fuzzer integrations found.")*
- **Confidence:** High — both validators independently confirmed the absence; two augmenters added targets and effort; corroborated live by the scorecard.

### G-002 — Not enrolled in the free continuous-fuzzing service
- **Category:** Missing
- **Expected:** Use of the free industry service that continuously fuzzes open-source projects.
- **Current:** No enrollment and no fuzz targets to enroll (see G-001).
- **Why it matters:** Continuous fuzzing catches regressions long after a one-time effort would have stopped looking.
- **Additional context (swarm):** The operations reviewer judged full enrollment disproportionate for a pre-1.0, effectively single-maintainer project and recommended a lighter self-hosted equivalent first; enrollment only makes sense once local fuzzing exists and proves fruitful.
- **Confidence:** High — both validators confirmed; deferral guidance is a priority judgment, not a dispute of the gap.

### G-003 — No reproducible-build capability
- **Category:** Missing
- **Expected:** Where feasible, builds that can be independently recreated bit-for-bit, so anyone can prove nothing was injected during compilation.
- **Current:** No reproducibility tooling or verification anywhere.
- **Why it matters:** Reproducibility is the strongest defense against a tampered build reaching users.
- **Additional context (swarm):** The actor sweep flagged this as **premature**: the project currently distributes nothing — no package registry publishing, no downloadable builds — so there is no consumer who could perform the comparison. It becomes load-bearing the moment a first release ships.
- **Confidence:** High — both validators confirmed the gap (one corrected a minor evidence overstatement; the finding stands).

### G-004 — Security scorecard now runs; findings untriaged, standards review open
- **Category:** Partial *(recategorized from Missing in the third evidence round — the scorecard workflow was added the same day this audit ran)*
- **Expected:** Running the industry's automated security-posture scorecard and considering the applicable security-verification standard.
- **Current:** The scorecard workflow landed on the trunk the morning of this audit (after the evidence snapshot) and has completed its first weekly-scheduled run, publishing results to the platform's scanning dashboard. Its 17 open findings are untriaged; the related best-practices badge is unpursued; the verification-standard half remains unconsidered (and is largely aimed at web applications).
- **Why it matters:** The dashboard now continuously tracks many of this report's other gaps automatically — its first run independently confirmed five of them at the exact predicted locations. The remaining work is triaging what it found.
- **Additional context (third round):** The new workflow is itself a model of the practices this report asks for — every building block pinned by fingerprint, minimal permissions — making it the in-repo template for fixing G-029.
- **Confidence:** High — verified live against the running scanning surface.

### G-005 — No software bill of materials
- **Category:** Missing
- **Expected:** A shareable, machine-readable inventory of everything the software is built from.
- **Current:** The raw dependency-lock records exist but are never transformed into a bill of materials.
- **Why it matters:** When a major vulnerability lands in a common component, a bill of materials is how anyone — including the maintainer — answers "are we affected?" in minutes instead of days.
- **Additional context (swarm):** Two agents independently flagged a trap: one bundled component is a hand-patched copy of a third-party library, and a mechanically generated bill of materials would misrepresent it as the unpatched original (see G-033). Generate the document only with that annotation in place.
- **Confidence:** High — both validators confirmed; two augmenters enriched.

### G-006 — Desktop app's dependencies are never checked or tested by automation
- **Category:** Missing
- **Expected:** Dependency checks and automated testing in the build pipeline for every part of the project.
- **Current:** Automation builds and tests only the core system. The desktop application — a full second technology ecosystem — is never installed, tested, type-checked, or audited by any automated process.
- **Why it matters:** The desktop app renders repository content on screen; a compromised or vulnerable component there runs code on the user's machine. Today nothing would notice.
- **Additional context (swarm):** The security reviewer found the app's pinned dependency list (with integrity fingerprints) is already committed, so scanning could start today with zero groundwork — and noted that because automation never installs the app, those integrity fingerprints are never actually verified anywhere. Two of the rendering components are pre-release, small-publisher packages that deserve watching.
- **Confidence:** High — all four checking agents confirmed.

### G-007 — Platform secret-leak scanning and push protection are switched off
- **Category:** Missing
- **Expected:** Sound operational practices for handling secrets, which for a platform-hosted project includes the platform's own leak scanning as a baseline.
- **Current:** All of the hosting platform's secret-scanning features, including the one that blocks a leaked credential before it lands, are confirmed disabled.
- **Why it matters:** The project has its own excellent commit-time secret scanner — but that scanner does not cover the path where content is exported to the hosting platform's own format. The platform's scanning is the intended backstop for exactly that surface, and it is off.
- **Additional context (swarm):** The security reviewer verified the project's first-party secret handling is genuinely strong (tokens hashed at rest, constant-time comparisons), which narrows this gap precisely to the platform surface — the most likely leak being a developer's own identity key file, a known footgun for this tool.
- **Confidence:** High — the live platform state was independently reproduced by the validator.

### G-008 — Automatic security-fix proposals are switched off
- **Category:** Missing
- **Expected:** Automated updates enabled wherever safely possible.
- **Current:** Scheduled version-update proposals exist for two ecosystems, but the separate platform feature that automatically proposes a fix when a *vulnerability* is announced is confirmed disabled.
- **Why it matters:** Detection without auto-remediation means every security fix waits for a human to notice a flag.
- **Additional context (swarm):** The security reviewer found a sharper edge: the update configuration deliberately ignores major-version bumps across the entire cryptography stack. Combined with this disabled feature, a critical advisory requiring a major upgrade of a core encryption component would surface through *no* automated channel — the project's highest-value attack target has its weakest alerting.
- **Confidence:** High — live platform state independently reproduced.

### G-009 — Changes must go through a proposal, but approval and passing checks are not required
- **Category:** Partial
- **Expected:** Requiring code review before changes merge.
- **Current:** A platform rule does force every change through a formal proposal and blocks direct or forced pushes — stronger than the first analysis believed. But the rule requires zero approvals, and a proposal with failing checks can still be merged.
- **Why it matters:** The proposal step exists, but nothing guarantees a second look or a green test run before code lands in the trunk of a security-sensitive project.
- **Additional context (swarm):** The validator corrected the original evidence (the protection exists under a newer mechanism the first pass didn't query). The operations reviewer added the honest nuance that a solo maintainer cannot approve their own proposal under platform rules, so requiring approvals needs a second reviewing principal first — but requiring passing checks costs nothing and closes the bigger hole. *(Third round: the live scorecard independently confirmed both halves — zero of the last 26 merged changes had an approval, and no status checks gate merging.)*
- **Confidence:** High — contradicted-then-corrected during validation, then independently corroborated by a second live tool.

### G-010 — No written internal procedure for handling a vulnerability report
- **Category:** Missing
- **Expected:** A documented internal process: who takes ownership, acknowledgment, tracking, triage, remediation planning, coordinated communication, and verification with the reporter.
- **Current:** The public policy tells reporters how to reach the project and what timelines to expect, but nothing documents what the maintainer actually does upon receipt.
- **Why it matters:** An undocumented process depends on one person's memory under pressure, and every future maintainer starts from zero.
- **Confidence:** High — both validators confirmed.

### G-011 — No written security-incident response plan
- **Category:** Missing
- **Expected:** An internal process for handling security incidents — supply-chain attacks, infrastructure compromise, data breaches — distinct from vulnerability reports.
- **Current:** No such document exists anywhere.
- **Why it matters:** "What do we do if a maintainer key is compromised or a dependency turns out to be backdoored" is a question to answer calmly in advance, not during the incident.
- **Confidence:** High — both validators confirmed.

### G-012 — No inventory of who and what holds which access
- **Category:** Missing
- **Expected:** A maintained list of access privileges.
- **Current:** No document records who holds administrative, publishing, domain, or signing-key access — and, after the swarm widened the scope, nothing records the *non-human* principals either: the automation tokens and the AI agents that hold write authority and make most of the day-to-day changes.
- **Why it matters:** Access you haven't inventoried is access you can't revoke in an incident, and it's a continuity risk for a small team.
- **Additional context (swarm):** The security reviewer added the project-specific top item: escrow-key custody is a standing ability to decrypt every private branch before publication — categorically more sensitive than any administrative role, and it belongs at the top of the list.
- **Confidence:** High — both validators confirmed; two augmenters widened scope.

### G-013 — No record of security-announcement subscriptions
- **Category:** Missing
- **Expected:** Subscriptions to security announcements for all languages, libraries, dependencies, and tools in use.
- **Current:** Automated advisory scanning covers the core ecosystem daily, but no document records any human subscription practice for the broader surface (the desktop framework, the second ecosystem, the toolchain).
- **Why it matters:** Automation catches what its database knows; a maintainer subscribed to the right feeds hears about emerging issues before databases update.
- **Confidence:** High — both validators confirmed the documentation absence.

### G-014 — The security policy names a private reporting channel that is switched off
- **Category:** Divergent *(upgraded from Missing after conclusive verification)*
- **Expected:** A working private reporting pipeline, with the platform's private-reporting feature as a recommended option.
- **Current:** The policy explicitly offers the platform's private vulnerability-reporting feature as a channel — and that feature is confirmed disabled. A report submitted the documented way is undeliverable. Only the email channel works.
- **Why it matters:** This is the single most user-facing defect in the report: the document that exists to help someone quietly report a security hole gives them a dead end.
- **Additional context (swarm):** The validator turned the original inference into proof by querying the setting directly. The related credit in the "already in good shape" list was corrected accordingly.
- **Confidence:** High — conclusively verified against the live platform.

### G-015 — No legal safe-harbor statement for good-faith researchers
- **Category:** Partial
- **Expected:** The disclosure policy should state legal authorization for good-faith security research.
- **Current:** The policy covers channels, report format, and timelines, but never says the project won't pursue action against researchers acting in good faith.
- **Why it matters:** Researchers increasingly skip projects that don't offer safe harbor; the absence deters exactly the people you want reporting.
- **Confidence:** High — both validators read the full policy.

### G-016 — No machine-readable security contact file for the website
- **Category:** Missing
- **Expected:** Mirroring the disclosure policy at the standard well-known web location.
- **Current:** No such file or template exists in the repository; the website is hosted elsewhere.
- **Why it matters:** The well-known location is where automated tooling and researchers look first.
- **Confidence:** High — both validators confirmed nothing in-repo feeds such a file.

### G-017 — No statement on whether a bug bounty exists
- **Category:** Partial
- **Expected:** The policy should state the existence *or explicit absence* of a bug bounty, with conditions.
- **Current:** The policy is silent in both directions.
- **Why it matters:** Reporters plan around expectations; silence invites mismatched ones.
- **Confidence:** High — both validators confirmed.

### G-018 — Reporters are never asked to hold findings in confidence
- **Category:** Partial
- **Expected:** The policy should request non-disclosure to third parties during the coordination window.
- **Current:** The project commits itself to a coordinated timeline but never asks the reporter for the reciprocal half.
- **Why it matters:** Coordinated disclosure only works if both sides know the terms.
- **Confidence:** High — both validators confirmed.

### G-019 — The security policy describes an outdated version of the product
- **Category:** Divergent
- **Expected:** Current documentation detailing function, safe usage, and security goals.
- **Current:** The policy has not been touched since launch while the security design advanced through three major revisions; it still describes the older encryption scheme and omits the newer secure transport. The project's own recent research notes admit this.
- **Why it matters:** From the reader's chair: "the one document meant to tell me the current security guarantees is telling me the wrong ones."
- **Additional context (swarm):** The validator strengthened this from self-assessment to hard history: the policy has exactly one edit ever, while the threat model advanced five times since.
- **Confidence:** High — verifiable from the document's change history.

### G-020 — No readable inventory of third-party components
- **Category:** Partial
- **Expected:** A readable list of third-party libraries, tools, and practices.
- **Current:** Key components appear as prose inside architecture rationale; the complete picture lives only in machine-oriented lock records, and the desktop ecosystem is not mentioned in the overview documents at all.
- **Why it matters:** Users and auditors deciding whether to trust the software need to see what it's made of without reverse-engineering lock files.
- **Additional context (swarm):** Present-day value is mainly for the upcoming professional audit (the packager audience doesn't exist until something is distributed); the hand-patched bundled component (G-033) must appear as a distinct class in any inventory.
- **Confidence:** High — both validators confirmed.

### G-021 — No statement about sensitive data and the impossibility of true deletion
- **Category:** Missing
- **Expected:** An explicit answer to "does this store personal or sensitive data?"
- **Current:** No document addresses it — for a product whose core purpose is storing secrets, protected content, and private branches.
- **Why it matters:** This product's history model means committed data can never be truly erased — revoked recipients keep what they already had, and rotation is not deletion. A user weighing legal erasure obligations against a history-preserving tool needs that stated plainly before they commit sensitive data, not discovered after.
- **Additional context (swarm):** The security reviewer stressed this must disclose the no-true-delete retention model directly, not be a boilerplate disclaimer. The actor sweep noted the most affected reader is the end user at the moment of deciding what to commit.
- **Confidence:** High — both validators confirmed zero coverage.

### G-022 — No standing rule for when releases or new dependencies trigger security review
- **Category:** Partial
- **Expected:** Planning security effort around milestones — releases, major features, new third-party components.
- **Current:** Security-focused work demonstrably happens (a dedicated hardening phase, an audit-preparation plan), but each instance was an ad-hoc decision; no standing policy says "changes of kind X trigger a review."
- **Why it matters:** Ad-hoc security effort stops the day attention moves elsewhere; a written trigger survives.
- **Additional context (swarm):** The operations reviewer split this honestly: a lightweight written checklist is proportionate now; a full release pipeline with provenance attestations is deferred until something actually ships.
- **Confidence:** High — both validators confirmed.

### G-023 — Whether the website mirrors the disclosure policy is unverified
- **Category:** Implicit
- **Expected:** Documentation available at all relevant locations including the project website.
- **Current:** The website exists but is outside this repository; its content was not fetched by any pass.
- **Why it matters:** Needs a five-minute manual check by someone with website access.
- **Confidence:** Low — unverifiable from the repository by design.

### G-024 — Whether maintainers are actually subscribed to security feeds is unverifiable
- **Category:** Implicit
- **Expected:** Maintainers subscribed to relevant announcement lists.
- **Current:** Nothing in a repository can prove or disprove a personal subscription.
- **Why it matters:** The documentable half is covered by G-013's fix; the rest is an honesty check only the maintainer can do.
- **Confidence:** Low — unverifiable by design.

### G-025 — Developer-device and infrastructure hygiene is largely unverifiable
- **Category:** Implicit
- **Expected:** Sound operational security for development devices and infrastructure.
- **Current:** What *is* visible looks good: automation runs on platform-hosted throwaway machines, holds only the minimal automatic token, and defaults to read-only permissions. Organization-level settings and device practices are outside repo scope.
- **Why it matters:** Mostly a confirm-and-document task, plus one small permission-tightening nit the reviewers spotted — which the live scorecard has since flagged as a high-severity finding of its own (a write permission granted at the top of one automation script instead of scoped to the step that needs it).
- **Confidence:** Low overall (organization/device half is unverifiable by design) — but the permission nit is now High, confirmed by two independent sources.

### G-026 — Legal reporting obligations are unaddressed
- **Category:** Implicit
- **Expected:** Incident reporting compliant with the operating jurisdiction's law, where required.
- **Current:** No stated legal entity or jurisdiction anywhere; a genuine silence, unremarkable for a small open-source project.
- **Why it matters:** Becomes relevant if the project formalizes; a maintainer/legal decision, not an engineering task.
- **Confidence:** Low — unverifiable by design.

### G-027 — Half the project's dependencies have no vulnerability feed at all
- **Category:** Partial
- **Expected:** Vulnerability awareness for *all* languages, libraries, and dependencies.
- **Current:** The core ecosystem has a live daily advisory feed that is demonstrably acted on. The desktop ecosystem — including the desktop framework's own security-advisory stream — has no detection mechanism whatsoever.
- **Why it matters:** A publicly announced vulnerability in a desktop component would sit unnoticed indefinitely.
- **Additional context (swarm):** One modern scanning tool can cover both ecosystems from the already-committed lock records in a single step.
- **Confidence:** High — all four checking agents confirmed.

### G-028 — Automated code analysis skips the desktop app's language
- **Category:** Partial
- **Expected:** Static analysis in automation "wherever possible."
- **Current:** The analysis service scans the core language and the automation scripts, but not the desktop app's language.
- **Why it matters:** The desktop renderer is exactly where untrusted repository content gets drawn on screen — the classic injection surface. The app's built-in content restrictions are a good mitigation, but they shouldn't be the only line of defense.
- **Additional context (swarm):** The fix is a one-line addition that ships independently of everything else — the cheapest coverage win in the report.
- **Confidence:** High — both validators confirmed the configuration.

### G-029 — Automation building blocks are referenced by movable labels, not fingerprints
- **Category:** Missing *(surfaced by the swarm — proposed independently by both augmenters)*
- **Expected:** Build-pipeline best practice (and a named check on the scorecard in G-004) is to reference third-party automation components by immutable fingerprint.
- **Current:** Every third-party building block in the automation pipeline is referenced by a movable label that its publisher — or someone who compromises its publisher — can silently repoint at different code.
- **Why it matters:** A repointed label executes attacker code inside the project's automation with that automation's privileges. This exact attack happened at ecosystem scale in 2025 and leaked credentials from thousands of projects. Because the update service already understands fingerprint references, fixing this costs nothing ongoing.
- **Additional context (third round):** The live scorecard now raises eight open findings for this, at exactly the locations this report predicted, and the just-added scorecard workflow itself demonstrates the correct fingerprint-pinned pattern to copy. One building block was version-bumped the same morning — still by movable label, so the gap stands.
- **Confidence:** High — proposed independently twice, confirmed by direct inspection, now corroborated live by the scorecard.

### G-030 — Incident planning ignores the compromised-AI-agent scenario
- **Category:** Missing *(surfaced by the actor-perspective sweep)*
- **Expected:** An incident process covering attacks on the project's development systems.
- **Current:** AI agents hold real write authority in this repository and do much of the work, yet no document contemplates a manipulated agent — tricked through crafted content into introducing a flaw or taking a harmful action — as an incident type with its own response (revoke agent credentials, audit agent-authored changes, revert).
- **Why it matters:** This is the incident class this project is *unusually* exposed to and the guide, written for human teams, cannot see. The response playbook differs meaningfully from the human-compromise cases.
- **Confidence:** Medium — single-source proposal, no contradiction, sibling of the well-confirmed G-011.

### G-031 — Nothing keeps private reports out of the automated public triage pipeline
- **Category:** Implicit *(surfaced by the actor-perspective sweep)*
- **Expected:** Reports handled privately by designated people, tracked internally.
- **Current:** The project's default triage is automated and public — agents process the public issue tracker, and automation auto-files findings there. No written boundary says a privately received vulnerability report must never enter that pipeline. **Important caveat:** no leak has occurred or been demonstrated; the automated filings to date concern already-public advisories. The gap is the absence of a guardrail, not an incident.
- **Why it matters:** From the reporter's chair: "I want to report quietly, but this project's triage runs bots over public issues — what guarantees my report doesn't become the next auto-filed public ticket?"
- **Confidence:** Low — genuine but single-source and resting on an interaction of policies rather than a direct checklist item.

### G-032 — Nothing requires a human in the review loop
- **Category:** Missing *(surfaced by the actor-perspective sweep)*
- **Expected:** Required code review before merging — whose intent is an independent second set of eyes with different failure modes than the author.
- **Current:** No rule — platform or written — requires the reviewer to be human, or even distinct in kind from the author. In an agent-operated repository, "reviewed" can be satisfied by one agent approving another agent's change, which shares the author's failure modes.
- **Why it matters:** The guide's control assumes something this project's operating model doesn't guarantee. Closing G-009 with approval counts alone would not close this.
- **Confidence:** Medium — the platform facts it rests on were verified by the validator; the framing is single-source.

### G-033 — A hand-patched bundled component has no visible provenance record
- **Category:** Partial *(surfaced jointly by the actor sweep and the security augmenter)*
- **Expected:** Supply-chain transparency — inventories and bills of materials that give users accurate context.
- **Current:** One third-party component is bundled in-tree as a hand-patched copy carrying a security fix ahead of its upstream, and the advisory scanner is configured to suppress the corresponding alert. The only records of this are a comment inside an automation script and a note inside the bundled folder itself — nothing at the level a security reader or tool would find. Any mechanically generated inventory today would misrepresent this component as the unpatched original.
- **Why it matters:** This is a correctness trap for G-005 and G-020: publish an inventory without the annotation and it will either falsely alarm (component looks vulnerable) or falsely reassure (component looks like clean upstream when it is a local fork).
- **Additional context (third round):** **The predicted trap has now occurred in a real tool run.** The scorecard's first scan read the raw dependency records and reported the patched component as an existing vulnerability — the exact false alarm this gap warned any version-keyed consumer would produce.
- **Confidence:** High — two independent proposers; the misrepresentation is now demonstrated, not predicted.

### G-034 — No hardening guide for people who run the server component
- **Category:** Partial *(surfaced by the actor-perspective sweep; flagged borderline in scope)*
- **Expected:** Attention to infrastructure security and hosting exposure.
- **Current:** The security *mechanisms* of the server component are thoroughly documented at the design level, but no task-oriented guide tells a first-time operator how to stand it up safely for a given trust level or what to do if their instance is attacked.
- **Why it matters:** Operators of the server are the actor whose infrastructure is on the line; design documents aimed at contributors don't serve them.
- **Confidence:** Low — single-source, self-flagged as the weakest-tier finding; arguably product documentation rather than an OSTIF-guide obligation.

### G-035 — The accepted-advisory list omits one member of its own accepted family
- **Category:** Partial *(added in the third evidence round, surfaced by disagreement between two live scanners)*
- **Expected:** Staying current with advisories means every deliberately accepted one is on the documented accepted-risk list with its removal condition — and independent scanners should agree with that documented posture.
- **Current:** The new scorecard's vulnerability check counts 18 known advisories in the dependency tree; the project's daily advisory scanner documents 17 accepted ones with removal conditions. The difference is a single advisory for an unmaintained desktop-toolkit binding — the *same family* as nine advisories already on the accepted list with a documented removal condition. This one member was simply left off, and the omission was invisible because the daily scanner only warns (rather than fails) on that advisory class.
- **Why it matters:** Not a new vulnerability — an accepted-risk record that is incomplete. Until fixed, the two scanners tell different stories, and anyone comparing them (an auditor, a future maintainer) has to rediscover why.
- **Confidence:** High — reconciled directly against both tools' live output and the dependency records.

> Engineers are the audience. Each entry adds technical fidelity to its Section 2 gap. Gaps with no entry (G-023, G-024, G-026) require a maintainer decision or an out-of-repo check rather than technical action — expected for Implicit items.

#### G-001 — Technical detail
- **Locations:** `crates/repo/src/wire.rs` (frame/length parsing); pack ingest via `crates/repo/src/stdio_transport.rs` / `transport.rs`; `crates/gitio/src/import.rs`; sealed-object/manifest parsing in `crates/repo/src/private.rs`; `.github/workflows/ci.yml:47-48`; `CONTRIBUTING.md:22-26`
- **Relevant identifiers:** canonical length-prefixed encoding (CLAUDE.md core invariant); `MAX_OBJECT_SIZE` (P28/ADR-0039)
- **Specifics:** No `proptest`/`quickcheck`/`cargo-fuzz` dependency or target exists anywhere in the workspace. ADR-0039 self-identifies a residual weakness: the wire frame-length header can allocate up to the cap before a chunk boundary is enforced.
- **Remediation direction:** (1) proptest roundtrip on the canonical encoding: `encode(decode(x)) == x` and `decode` never panics on arbitrary bytes — runs on the pinned stable toolchain with zero CI change. (2) One `cargo-fuzz` target on the `wire.rs` decode entry point in a separate nightly-toolchain scheduled job. Widen to pack ingest and git import after.
- **Effort signal:** Small (proptest) / Medium (cargo-fuzz nightly job) — split per the devops review.
- **Risks / dependencies:** None for proptest. cargo-fuzz needs nightly + sanitizers; keep it out of the merge-gating path.

#### G-002 — Technical detail
- **Locations:** (absent) no `.clusterfuzzlite/` or `fuzz/` directory
- **Specifics:** OSS-Fuzz onboarding requires fuzz targets (G-001) plus a `projects/` PR against google/oss-fuzz and ongoing external triage.
- **Remediation direction:** Defer. Intermediate step: ClusterFuzzLite running the same cargo-fuzz targets in-repo CI on PRs.
- **Effort signal:** Large — external onboarding and standing triage burden.
- **Risks / dependencies:** Strictly downstream of G-001. Reopen trigger: targets exist and local fuzzing finds real bugs.

#### G-003 — Technical detail
- **Locations:** `Cargo.toml:26` (`publish = false`); `.github/workflows/` (no release workflow)
- **Specifics:** No `--remap-path-prefix`, `SOURCE_DATE_EPOCH`, or attestation tooling. Nothing is distributed, so no consumer can perform a comparison today.
- **Remediation direction:** Defer until a first distributed artifact. Rust-core determinism is tractable then; the Tauri bundle is the hard case (platform installers are notoriously non-deterministic).
- **Effort signal:** Large — and near-zero present value per the swarm.
- **Risks / dependencies:** Blocked behind a release pipeline (G-022 deferred half / T-24).

#### G-004 — Technical detail
- **Locations:** `.github/workflows/scorecard_analysis.yml` (added on `main` in #74/#75, post-dating the audit's evidence snapshot `d7106e5`; weekly cron + push; `publish_results: true`; SARIF → code scanning); 17 open Scorecard alerts (#4–#20) on the code-scanning surface, uploaded 2026-07-18T08:29Z from commit `d6e60ac`
- **Specifics:** The workflow itself is fully SHA-pinned (`ossf/scorecard-action@4eaacf05… # v2.4.3`, `actions/checkout@9c091bb2… # v7.0.0`, `github/codeql-action/upload-sarif@8aad20d1… # v4.36.2`), `permissions: read-all` top-level with job-scoped `security-events: write` + `id-token: write`, `persist-credentials: false`. First-run check scores: PinnedDependencies 2, BranchProtection 3, CodeReview 0, Fuzzing 0, Vulnerabilities 0, TokenPermissions 9, SAST 9, CITests 9; `CIIBestPracticesID` (OpenSSF badge) 0; `MaintainedID` 0 is informational only (repo < 90 days old).
- **Remediation direction:** Triage the 17 open alerts (this report's todos cover the substantive ones: T-2/T-9/T-13/T-20/T-26); optionally pursue the OpenSSF best-practices badge; skip deep OWASP ASVS investment (web-app standard; minimal applicable subset).
- **Effort signal:** Small — the setup half is done; alert triage remains.
- **Risks / dependencies:** None.

#### G-005 — Technical detail
- **Locations:** `Cargo.lock` (workspace root); `apps/desktop/package-lock.json`
- **Remediation direction:** `cargo-cyclonedx` (or `cargo sbom` for SPDX) + `@cyclonedx/cyclonedx-npm`/`npm sbom` as CI artifacts — both lockfiles are committed, so inputs exist. **Must** carry the G-033 provenance annotation for `vendor/glib-0.18.5-patched` before being published anywhere.
- **Effort signal:** Small for the CI artifact; release-attachment deferred with G-022's pipeline.
- **Risks / dependencies:** G-033 is a correctness precondition.

#### G-006 — Technical detail
- **Locations:** `.github/workflows/ci.yml` (Rust-only); `apps/desktop/package.json` (declares `typecheck`: `tsc -b`, `test`: `vitest run`); `apps/desktop/package-lock.json` (lockfileVersion 3, ~234 packages, sha512 integrity hashes — never verified because no workflow runs any npm command)
- **Remediation direction:** One `desktop` CI job: `npm ci` → `npm audit --audit-level=high` (or `osv-scanner`) → `npm run typecheck` → `npm run test`.
- **Effort signal:** Small — scripts and lockfile already exist.
- **Risks / dependencies:** Watch items: `@pierre/trees@1.0.0-beta.5`, `@pierre/theming@0.0.2` (pre-release, small-publisher, in the content-rendering path).

#### G-007 — Technical detail
- **Locations:** GitHub repo settings (live API: `security_and_analysis` — `secret_scanning`, `secret_scanning_push_protection`, non-provider patterns, validity checks all `disabled`)
- **Specifics:** The P5 scanner (ADR-0017) gates sc-commit content only; the git export/mirror bridge (P9/P18, ADR-0016/0028) materializes content into GitHub-hosted git where only GitHub's scanning applies. First-party token hygiene is strong (`crates/repo/src/serve_tokens.rs:104-131`, BLAKE3-at-rest + constant-time compare) — the risk is leaked identity keys (`scl-sk-<hex>`) or PATs on the git side.
- **Remediation direction:** Enable secret scanning + push protection in repo settings.
- **Effort signal:** Trivial — toggles.

#### G-008 — Technical detail
- **Locations:** GitHub repo settings (`dependabot_security_updates: disabled`, live-verified); `.github/dependabot.yml:11-29` (semver-major ignores across `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `sha2`, `hkdf`, `rand_core`, `rand_chacha`)
- **Specifics:** A critical advisory requiring a major bump on an AEAD/signature crate surfaces through neither the scheduled version PRs (major ignored) nor security updates (disabled); daily cargo-audit only flags.
- **Remediation direction:** Enable dependency graph → Dependabot alerts → security updates. Consider whether the RustCrypto major-version ignore should carve out security advisories.
- **Effort signal:** Trivial — one-click setting.

#### G-009 — Technical detail
- **Locations:** Live ruleset `id 18739705` on `main`: rules `deletion`, `non_fast_forward`, `pull_request` with `required_approving_review_count: 0`, `required_reviewers: []`, `require_code_owner_review: false`; **no** `required_status_checks` rule. Corroborated by live Scorecard alerts #14 (`CodeReviewID` score 0: "Found 0/26 approved changesets") and #4 (`BranchProtectionID` score 3: "does not require approvers… no status checks found to merge onto branch 'main'")
- **Remediation direction:** Add `required_status_checks` (the `ci` + `codeql` checks, require branches up to date). Hold `required_approving_review_count > 0` until a second reviewing principal exists (a solo maintainer cannot self-approve) — that half is tracked as G-032/T-16.
- **Effort signal:** Small — ruleset edit.
- **Risks / dependencies:** Rests on live GitHub configuration; **reverify the ruleset state before acting** (validator flag).

#### G-010 — Technical detail
- **Locations:** `SECURITY.md:31-59` (external-facing only); `docs/agents/issue-tracker.md` (no security handling)
- **Remediation direction:** Write the internal response process: named responsible role, acknowledgment step, private tracking location, triage/impact analysis, remediation planning, third-party comms, reporter verification. Incorporate the G-031 boundary (below).
- **Effort signal:** Small–Medium — documentation.

#### G-011 — Technical detail
- **Locations:** (absent) — `docs/THREAT-MODEL.md` is cryptographic/protocol scope, not operational
- **Remediation direction:** Write an incident-response doc covering: maintainer key compromise, backdoored dependency discovered post-hoc, org/account takeover, data breach — **plus the compromised-agent class (G-030)**: revoke agent credentials, audit agent-authored commits, revert.
- **Effort signal:** Medium — documentation with real decisions.

#### G-012 — Technical detail
- **Locations:** (absent) — proposed `docs/agents/ACCESS.md`
- **Specifics:** Must cover humans (GitHub org/repo admin, DNS for git-agentic.com, signing-key custody, crates.io — currently N/A with `publish = false`) **and** non-human principals: per-workflow `GITHUB_TOKEN` scopes (`audit.yml:23-28` grants `checks: write`, `issues: write`; `codeql.yml` grants `security-events: write`) and agent `gh`-CLI write authority. **Escrow-key custody first** — a standing decrypt privilege over every private branch pre-publish (THREAT-MODEL, ADR-0044).
- **Effort signal:** Small — a single page; resist over-engineering.

#### G-013 — Technical detail
- **Locations:** (absent)
- **Remediation direction:** Short doc listing feeds and who watches them: RustSec-announce, Tauri GHSA, npm/OSV for the desktop tree, GitHub advisory notifications, toolchain announcements.
- **Effort signal:** Small.

#### G-014 — Technical detail
- **Locations:** `SECURITY.md:34-38`; live API `private-vulnerability-reporting` → `{"enabled": false}`
- **Remediation direction:** **Maintainer decision:** enable the toggle (preferred — it's the better channel) or remove the claim from SECURITY.md. Either way the text and the configuration must agree. Bundle with the G-019 rewrite (same file, same PR).
- **Effort signal:** Trivial (toggle) — or part of the T-8 SECURITY.md PR.

#### G-015 / G-017 / G-018 — Technical detail (single SECURITY.md revision)
- **Locations:** `SECURITY.md` (full file, 59 lines)
- **Remediation direction:** In one revision add: a good-faith safe-harbor statement; an explicit bug-bounty status ("no bounty at this time" suffices); a reporter non-disclosure request mirroring the existing 90-day project commitment.
- **Effort signal:** Small — one document PR shared with G-014/G-019.

#### G-016 — Technical detail
- **Locations:** (absent); website is out-of-repo
- **Remediation direction:** Add an RFC 9116 `security.txt` template in-repo; deploying to `/.well-known/` on git-agentic.com is a website task (pairs with the G-023 manual check).
- **Effort signal:** Trivial in-repo; website deployment external.

#### G-019 — Technical detail
- **Locations:** `SECURITY.md` (single commit `77fb32e` ever; describes pre-P32/P33 design; still frames protected paths as convergent encryption; omits `sc+https://`); `docs/THREAT-MODEL.md` (5 later commits through P32/P33/P34); `docs/research/cryptography-audit-options.md:139-140` (project's own admission)
- **Remediation direction:** Reconcile SECURITY.md with P32 (TLS) and P33 (randomized sealing) — already a named precondition in the audit-prep research note. Same PR as G-014/015/017/018.
- **Effort signal:** Small.

#### G-020 — Technical detail
- **Locations:** `CLAUDE.md` "Stack & tooling" (prose, no npm tree); `Cargo.lock`; `apps/desktop/package-lock.json`
- **Remediation direction:** One human-readable inventory doc spanning both ecosystems, flagging vendored/patched deps (G-033) as a distinct class. Can be partially generated, then annotated.
- **Effort signal:** Small.

#### G-021 — Technical detail
- **Locations:** (absent) — zero matches for PII/personal-data/GDPR anywhere in docs
- **Remediation direction:** A data-handling statement covering: what sensitive data the system stores (secrets, protected content, private branches), where it lives, what leaves the machine, and — explicitly — the append-only / rotation-≠-erasure retention model (ADR-0019, THREAT-MODEL) and its tension with erasure regimes.
- **Effort signal:** Small — the source material all exists in ADRs/THREAT-MODEL.

#### G-022 — Technical detail
- **Locations:** `CONTRIBUTING.md` (no release/security cadence); `ROADMAP.md` P28 (reactive precedent)
- **Remediation direction:** Now: a checklist in CONTRIBUTING.md — "new dependency, or any change touching `crypto`/`tlsio`/transport → threat-model + audit pass before merge." Deferred: tag-triggered release pipeline with SLSA provenance (`slsa-framework/slsa-github-generator`) once a first artifact ships, attaching the G-005 SBOM.
- **Effort signal:** Small (checklist) / Large (pipeline, deferred).

#### G-025 — Technical detail
- **Locations:** `.github/workflows/audit.yml:23-28` (workflow-top-level `checks: write` + `issues: write` — applies to every step incl. checkout). Corroborated by live Scorecard alert #5 (`TokenPermissionsID`, high severity, on `audit.yml:25`)
- **Remediation direction:** Scope write permissions to the job/step that needs them; confirm org-level 2FA; document the baseline ("GitHub-hosted ephemeral runners only, `GITHUB_TOKEN` only, no long-lived cloud keys").
- **Effort signal:** Small — confirm-and-document.

#### G-027 — Technical detail
- **Locations:** `.github/dependabot.yml` (no `npm` ecosystem entry); `.github/workflows/audit.yml` (Rust-only feed)
- **Remediation direction:** Add `package-ecosystem: npm`, `directory: /apps/desktop` to dependabot.yml — same PR as the G-006 CI job. Alternative single-tool path: `osv-scanner` over both lockfiles.
- **Effort signal:** Trivial.

#### G-028 — Technical detail
- **Locations:** `.github/workflows/codeql.yml:22-29` (matrix: `rust`, `actions` only)
- **Remediation direction:** Add `- language: javascript-typescript` / `build-mode: none` to the matrix, reusing the existing `paths-ignore`. Needs no npm install; ships independently of G-006 (devops adjudication: do **not** chain them).
- **Effort signal:** Trivial — one matrix entry.

#### G-029 — Technical detail
- **Locations:** `.github/workflows/ci.yml:24,39,42`; `codeql.yml:31,32,42`; `audit.yml:35,36` — all `uses:` refs are mutable tags (`actions/checkout@v7`, `dtolnay/rust-toolchain@1.96.1`, `Swatinem/rust-cache@v2`, `github/codeql-action/{init,analyze}@v4` after #72's v3→v4 bump — still a tag, `rustsec/audit-check@v2`). Corroborated by 8 open live Scorecard `PinnedDependenciesID` alerts (#6–#13) at exactly these lines.
- **Specifics:** Third-party pins first (`Swatinem/rust-cache`, `rustsec/audit-check`, `dtolnay/rust-toolchain`); GitHub-owned `actions/*`/`github/*` are lower blast-radius. Token scopes in reach of a compromised action: `issues: write`, `checks: write` (audit), `security-events: write` (codeql). Precedent: tj-actions/changed-files, CVE-2025-30066.
- **Remediation direction:** Pin every action to a full 40-char commit SHA with a `# vX` comment — copy the pattern from the repo's own `scorecard_analysis.yml`, which already does this correctly. The existing `github-actions` dependabot ecosystem keeps SHAs updated — zero ongoing cost.
- **Effort signal:** Small.

#### G-030 — Technical detail
- **Locations:** `docs/agents/issue-tracker.md`, `docs/agents/triage-labels.md`, `CLAUDE.md` "Agent skills" (agent write authority); no incident doc (G-011)
- **Remediation direction:** Include an agent-compromise section in the G-011 incident doc: detection signals (anomalous agent commits/labels), response (revoke agent credentials/sessions, audit agent-authored changes since last-known-good, revert), and injection-source review (issue bodies, dependency docs, upstream skills).
- **Effort signal:** Folded into G-011's Medium.

#### G-031 — Technical detail
- **Locations:** `docs/agents/issue-tracker.md` + `triage-labels.md` (public agent triage by design); `.github/workflows/audit.yml:26-28` (`issues: write`, auto-files findings)
- **Remediation direction:** One boundary rule in the G-010 process doc: "reports received via the private channel are never filed, labeled, or processed through the public/agent triage pipeline; agents triaging public issues must stop and escalate on content resembling an undisclosed vulnerability."
- **Effort signal:** Trivial — a paragraph, folded into T-16.
- **Risks / dependencies:** No demonstrated leak; guardrail-in-advance.

#### G-032 — Technical detail
- **Locations:** Ruleset 18739705 (`required_reviewers: []`, count 0); `CONTRIBUTING.md` (no reviewer-identity requirement)
- **Remediation direction:** Written policy: agent-authored changes require a human reviewer distinct from the author (enforce via ruleset review-count + CODEOWNERS when a second principal exists). Distinct from G-009's status-check fix.
- **Effort signal:** Small (policy now) — enforcement grows with the team.

#### G-033 — Technical detail
- **Locations:** `Cargo.toml:9-10` (`[patch.crates-io] glib = { path = "vendor/glib-0.18.5-patched" }`); `audit.yml:39-48` (RUSTSEC-2024-0429 ignore + "matches versions only" comment); `vendor/glib-0.18.5-patched/PROVENANCE.md` (exists but unreferenced from any top-level doc)
- **Specifics:** `Cargo.lock` records `glib 0.18.5` with no marker distinguishing the patched vendor copy — any mechanical SBOM/inventory misrepresents it. **Demonstrated live:** Scorecard alert #18 (`VulnerabilitiesID`) now reports "Project is vulnerable to: RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g" — the OSV check read the lockfile version and produced exactly the predicted false positive against the patched copy.
- **Remediation direction:** Surface the provenance (patch content, rationale, removal trigger = upstream fix) in the G-020 inventory and as an annotation in any G-005 SBOM; link PROVENANCE.md from a top-level security doc.
- **Effort signal:** Small.

#### G-034 — Technical detail
- **Locations:** ADR-0036/0040/0041/0042 (mechanisms); `docs/THREAT-MODEL.md` (boundaries); `ROADMAP.md` Deferred (~685-697, known listener gaps without interim mitigations)
- **Remediation direction:** Deferred: a task-oriented `sc serve` operator guide (minimum flag set per trust level, token/TLS-key custody, incident steps). Reopen when operators deploy at scale or user-facing ops docs are written.
- **Effort signal:** Medium.

#### G-035 — Technical detail
- **Locations:** Live Scorecard alert #18 (`VulnerabilitiesID`: 18 advisories) vs `.github/workflows/audit.yml:48` on `origin/main` (`ignore:` list: 17 advisories). Set-difference: **RUSTSEC-2024-0413** (`atk` 0.18.2 in `Cargo.lock`; "gtk-rs GTK3 bindings - no longer maintained", confirmed via the OSV API)
- **Specifics:** Same GTK3-unmaintained family as the nine ignored siblings (RUSTSEC-2024-0411/0412/0414–0420) whose removal gate ("remove… when Tauri 3 moves the stack to GTK4") is documented in `audit.yml:39-45`. cargo-audit doesn't fail on it because unmaintained-class advisories warn rather than error — so the omission surfaced only when Scorecard's OSV check counted it.
- **Remediation direction:** Add `RUSTSEC-2024-0413` to the `ignore:` list under the existing GTK3 removal-gate comment (one line), keeping the two scanners' stories consistent; longer-term, the G-033/T-11 provenance work is where the acceptance record should live.
- **Effort signal:** Trivial — one list entry.
- **Risks / dependencies:** None; the Scorecard alert itself will only close via dismissal or the GTK4 migration, since its OSV check does not honor cargo-audit ignores.

---

## 4. Swarm Findings

### How this section relates to sections 2 and 3

Entries are grouped by the kind of signal the swarm produced and reference the affected gap IDs. Use this section to gauge confidence and spot disagreements worth a second look before acting.

### Swarm composition

- **Validators run:**
  - `evidence-based-investigator` — independent repo-side re-verification of every cited file and grep; no API access, so the live-platform halves of G-007/008/009/014 were explicitly left to the other validator.
  - `adversarial-validator` — full re-verification *with* live API access; independently reproduced the security-settings block, the ruleset configuration, and the private-reporting toggle. Produced the one material counter-finding (G-009's mechanism).
- **Augmenters run:**
  - `junior-developer` (actor-perspective sweep) — enumerated 10 actor classes; surfaced the AI-agent-contributor and non-human-principal classes the human-framed guide structurally cannot see (→ G-030/031/032/034, and G-033 jointly).
  - `adversarial-security-analyst` — supply-chain, secrets, disclosure, and crypto-custody exploit context (→ G-029 jointly).
  - `devops-engineer` — effort estimates and do-now/do-soon/defer ranking calibrated to a pre-1.0, solo-maintainer, source-only project (→ G-029 jointly).
- **Total runs:** 5, plus a second analyzer pass that independently re-verified every swarm claim before minting G-029…G-034 (none were accepted on assertion alone), and a project-manager synthesis run consolidating this section.

### Confirmations

- **G-001…G-008, G-010…G-013, G-015…G-022, G-027, G-028** — confirmed independently by **both validators** via direct grep/find/git-history checks; every spot-checked citation matched file content exactly. The augmenters added named targets, effort estimates, and severity refinements on top (see Augmentations).
- **G-007 / G-008** — the adversarial validator reproduced the exact live disabled-settings block the investigator could only confirm repo-side. Two-agent confirmation, one with live proof.
- **G-014** — upgraded from inference to proof: the private-reporting toggle queried directly, `{"enabled": false}`. Conclusive.
- **G-019** — strengthened: the security policy has exactly one commit ever, while the threat model advanced five times through three major design revisions — git-verifiable drift, not just the project's own self-assessment.
- **G-029** — proposed **independently by two augmenters**, therefore checked first and hardest; confirmed by direct inspection of every automation reference with no exceptions.
- **G-033** — surfaced jointly by two agents from different vantages (auditor-transparency and supply-chain-correctness); the patch and its alert-suppression are directly cited in the repository.

### Contradictions

- **G-009** — **Disagreement:** the primary analysis's evidence (legacy branch-protection query returning "not protected" → "nothing prevents a direct push") was **wrong**; an active ruleset blocks direct pushes, force-pushes, and deletion for everyone with no bypass. **Adjudication:** mechanism corrected in the second pass; the surviving gap holds (zero required approvals, no required status checks — a proposal with failing checks can merge). Category stays Partial. Rests on live platform configuration — **reverify before acting** (T-9).
- **Satisfied over-credit #1** — **Disagreement:** the first pass credited "private-reporting channel explicitly named, including the platform's native mechanism" as satisfied; the validator proved the platform-native half is disabled. **Adjudication:** only the email channel is live; credit corrected in Section 1 and tracked as G-014 (Divergent).
- **Satisfied over-credit #2** — **Disagreement:** "CI *enforces* linting, formatting, and the full test suite on every PR" overstated — the checks run on every proposal but a red run does not block merge (no required-status-checks rule). **Adjudication:** downgraded to "runs" in Section 1; the enforcement half lives in G-009/T-9, not as a new gap.

### Augmentations

- **G-001** — security: the fuzz recommendation has a concrete, pre-motivated target — the project's own design record admits a residual input-length weakness in the wire parser. devops: malformed-input crashes are a remote denial-of-service on the server component; decoder targets before generic property tests.
- **G-002** — devops: use the lightweight self-hosted continuous-fuzzing route before the external service; the external service is disproportionate for a pre-1.0 solo project.
- **G-003 / G-005 / G-020 (packager angle)** — actor sweep: the most-affected actor (downstream packager / binary consumer) does not exist yet — nothing is published or distributed. Premature-until-distribution; present-day value survives only via the auditor vantage (G-033).
- **G-004** — devops: cheapest forcing-function in the set; its dashboard automatically tracks G-001, G-009, G-022, and G-029 thereafter.
- **G-006 / G-027** — security: one modern scanner covers both ecosystems from the two committed lockfiles; the desktop framework's own advisory stream currently has no detection path; two pre-release small-publisher rendering components deserve watching. The committed integrity fingerprints are never actually verified because automation never installs the app.
- **G-007** — security: first-party secret handling is strong (hashed at rest, constant-time comparison), which narrows this gap precisely to the platform backstop for the export/mirror path — most plausibly a developer's own identity key file, a documented footgun of this tool.
- **G-008** — security: the update configuration ignores major-version bumps across the entire cryptography stack; combined with the disabled toggle, the highest-value attack target has the weakest automated alerting in the repository.
- **G-009 / G-032** — devops: a solo maintainer cannot approve their own proposal under platform rules, so approval requirements need a second reviewing principal first; require passing checks now, approvals when the team grows.
- **G-012** — security: escrow-key custody — a standing ability to decrypt every private branch before publication — belongs at the top of the inventory, above any administrative role. Actor sweep: the inventory must include non-human principals, who make most of the writes.
- **G-019 / G-021** — actor sweep: the most-affected reader is the end user consulting the policy to decide what is safe to commit, not the auditor.
- **G-021** — security: the statement must plainly disclose the no-true-delete retention model (rotation is not erasure; revoked recipients keep what they had) — the exact tension a user weighing legal erasure obligations needs stated up front.
- **G-028** — security: the desktop renderer is where untrusted repository content crosses into a browser-engine view — the classic injection surface; content-security restrictions are a mitigation, not a substitute for analysis. devops: one-line addition, ships independently.
- **G-029** — security: not theoretical — the same movable-label attack compromised a widely used automation component in 2025 (CVE-2025-30066), leaking credentials across thousands of projects. devops: the update service already maintains fingerprint pins, so the fix has zero ongoing cost.
- **G-030 / G-031 / G-032** — actor sweep: all three exist because the guide assumes human teams; this repository's agent-operated model is the actor class the guide structurally cannot see.

### Post-swarm live-evidence addendum (third round, 2026-07-18)

After the swarm ran and the report was first rendered, the live code-scanning surface was checked at the user's request — and it had changed the same morning: a scorecard workflow (recommended by G-004/T-1) had just been added and completed its first run. That run acts as an unplanned sixth, fully independent check on this report:

- **Corroborated at the exact predicted locations:** G-029 (8 pinned-dependencies alerts on the same file lines), G-009/G-032 (0 of 26 merged changes approved; no status checks gate merging), G-025's permission nit (high-severity token-permissions alert on the same line), G-001/G-002 (fuzzing scored 0).
- **Demonstrated, not just predicted:** G-033 — the scanner reported the patched bundled component as an existing vulnerability, the exact false positive this report warned about.
- **Changed:** G-004 recategorized Missing → Partial (the scorecard now runs; its findings await triage).
- **New:** G-035 — reconciling the scanner's 18-advisory count against the audit workflow's 17-entry accepted list exposed one undocumented member of an already-accepted advisory family.
- **Clean signals:** zero open code-analysis alerts (three historical memory-safety findings fixed); test-coverage and analysis-coverage checks scored 9/10.

### Confidence summary

| Confidence | Gap IDs | Interpretation |
|------------|---------|----------------|
| **High** (27) | G-001, G-002, G-003, G-004, G-005, G-006, G-007, G-008, G-009, G-010, G-011, G-012, G-013, G-014, G-015, G-016, G-017, G-018, G-019, G-020, G-021, G-022, G-027, G-028, G-029, G-033, G-035 | Confirmed by both validators and/or two independent sources with reproduced evidence (G-009 and G-029/G-033 additionally corroborated by the live scorecard run); safe to act on. |
| **Medium** (2) | G-030, G-032 | Solid fact base; single-augmenter sharpenings without contradiction (G-032's platform facts verified; its policy framing single-source). |
| **Low** (6) | G-023, G-024, G-025, G-026, G-031, G-034 | Unverifiable-from-repo by design, or single-source with self-flagged caveats; adjudicate or check manually before investing. |

---

## 5. Actionable TODO List

The prioritized work plan, consolidated by the project-manager synthesis from the devops ranking, the security severity notes, and the actor sweep's premature-until-distribution flags. Every one of the 35 gaps traces to a todo or to the explicit "not an engineering task" list at the end.

> **Status (2026-07-18, see Section 0):** the **Now** and **Soon** tiers below are ✅ **done** (PRs #76–#87). The **Deferred** tier is open by design. Rows are left as written for the audit trail; the checkmarks record what shipped.

### Tier: Now ✅ done — small effort, high value, actionable on a source-only repo today

| # | Closes | Action | Effort |
|---|--------|--------|--------|
| T-1 | G-004 | ~~Add the `ossf/scorecard-action` workflow~~ **Partly done** (landed same-day as #74/#75, before this report was finished). Remaining: triage the 17 open Scorecard alerts — the substantive ones map to T-2, T-9, T-13, T-20, T-26; `MaintainedID` is informational; decide on the OpenSSF badge. | Small |
| T-2 | G-029 | Pin all GitHub Actions to full 40-char commit SHAs (third-party first: `Swatinem/rust-cache`, `rustsec/audit-check`, `dtolnay/rust-toolchain`). Copy the pattern from the repo's own `scorecard_analysis.yml`, which is already correctly SHA-pinned. Closes 8 open Scorecard alerts. Dependabot already maintains SHA pins — no ongoing cost. | Small |
| T-3 | G-028 | Add `- language: javascript-typescript` / `build-mode: none` to the CodeQL matrix. Ships independently — do not chain to T-4. | Trivial |
| T-4 | G-006, G-027 (detection) | Add a `desktop` CI job: `npm ci` → `npm audit --audit-level=high` (or `osv-scanner`) → `npm run typecheck` → `npm run test`. The renderer currently has no CI at all. | Small |
| T-5 | G-027 | Add `package-ecosystem: npm` / `directory: /apps/desktop` to `.github/dependabot.yml` (same PR as T-4). | Trivial |
| T-6 | G-008 | Enable the Dependabot security-updates toggle (dependency graph + alerts first). The only automated safety net the npm tree and the major-version-ignored RustCrypto stack would get. | Trivial |
| T-7 | G-007 | Enable GitHub secret scanning + push protection — the backstop for the git export/mirror surface the in-house scanner doesn't cover. | Trivial |
| T-8 | G-014, G-019, G-015, G-017, G-018 | **Single SECURITY.md PR:** enable private vulnerability reporting (or remove the claim — maintainer decision); reconcile stale pre-P32/P33 claims; add safe-harbor language, bug-bounty status, and a reporter non-disclosure request. | Small |
| T-9 | G-009 | Extend the `main` ruleset with required status checks (`ci`, `codeql`; branches up to date). Hold required-approval count at 0 until a second reviewing principal exists (see T-16). **Reverify live ruleset state first.** Closes the substantive half of Scorecard alerts #4/#14. | Small |
| T-26 | G-035 | Add `RUSTSEC-2024-0413` (`atk`, GTK3-unmaintained family) to `audit.yml`'s `ignore:` list under the existing GTK3 removal-gate comment, so cargo-audit and Scorecard tell one consistent story. | Trivial |

### Tier: Soon ✅ done — small-to-medium; auditor and documentation value now

| # | Closes | Action | Effort |
|---|--------|--------|--------|
| T-10 | G-005, G-033 | Generate a two-ecosystem SBOM as a CI artifact (`cargo-cyclonedx` + npm), **with the patched-glib provenance annotation** — publishing without it misrepresents the dependency. | Small |
| T-11 | G-020, G-033 | Write a human-readable third-party inventory spanning both ecosystems; vendored/patched deps as a distinct class; link `vendor/glib-0.18.5-patched/PROVENANCE.md` from a top-level doc. | Small |
| T-12 | G-001 (start) | Add a proptest roundtrip on the canonical encoding (`encode(decode(x)) == x`; no panic on arbitrary bytes). Free on the pinned stable toolchain; guards a core invariant. | Small |
| T-13 | G-001 (advance), G-002 (setup) | One `cargo-fuzz` nightly target on the `wire.rs` decode path — ADR-0039's self-identified weakness; remote-DoS blast radius on `sc serve`. | Medium |
| T-14 | G-012 | Write a single-page `docs/agents/ACCESS.md`: escrow-key custody at the top, then human roles (admin, DNS, signing keys), then non-human principals (per-workflow token scopes, agent `gh` authority). | Small |
| T-15 | G-022 | Add a release/security-review checklist to CONTRIBUTING.md: "new dependency, or any change touching `crypto`/`tlsio`/transport → threat-model + audit pass before merge." | Small |
| T-16 | G-010, G-031, G-032 | Document the internal vulnerability-response process, including (a) the boundary keeping private reports out of the public agent-triage pipeline and (b) a human-in-the-loop review requirement for agent-authored changes. | Small–Medium |
| T-17 | G-011, G-030 | Document the security-incident response process, including the compromised / prompt-injected agent class (revoke agent credentials, audit agent-authored commits, revert). | Medium |
| T-18 | G-021 | Write the sensitive-data statement disclosing the no-true-delete / rotation-≠-erasure retention model. | Small |
| T-19 | G-013, G-024 (doc half) | Document maintainer security-feed subscriptions (RustSec, Tauri GHSA, npm/OSV, GitHub advisories, toolchain). | Small |
| T-20 | G-025 | Record the CI/infra opsec baseline (ephemeral hosted runners, `GITHUB_TOKEN` only), confirm org 2FA, and scope `audit.yml`'s write permissions from workflow-level to job/step. | Small |
| T-21 | G-016 | Add an RFC 9116 `security.txt` template; deploying to `/.well-known/` is a website task (pairs with the G-023 manual check). | Trivial |

### Tier: Deferred ⏳ open by design — disproportionate now; reopen on a concrete trigger

| # | Closes | Action | Effort | Reopen trigger |
|---|--------|--------|--------|----------------|
| T-22 | G-002 | OSS-Fuzz onboarding (use ClusterFuzzLite in-repo first). | Large | T-13 targets exist **and** local fuzzing finds real bugs. |
| T-23 | G-003 | Reproducible-build tooling (Rust core first; the Tauri bundle is the hard case). | Large | First distributed release artifact exists. |
| T-24 | G-022 (pipeline half) | Full release pipeline with SLSA build-track provenance, attaching the T-10 SBOM. | Large | First published artifact (crates.io or signed desktop bundle). |
| T-25 | G-034 | Operator-facing `sc serve` hardening/incident runbook. | Medium | Operators deploy at scale, or user-facing ops docs get written. |

### Not engineering tasks — maintainer decisions / out-of-repo checks (so all 35 gaps trace)

- **G-023** — five-minute manual check: does git-agentic.com mirror the disclosure policy (and can it host the T-21 `security.txt`)?
- **G-026** — jurisdiction/legal-entity question; a maintainer/legal decision, not a todo.
- **G-024** — the documentable half is T-19; whether a human is actually subscribed is an honesty check only the maintainer can perform.
- **G-025** — beyond T-20's confirm-and-document, device-level hygiene is out of repo scope.
- **G-031** — no standalone task; folded into T-16 as the boundary paragraph.

### Flagged for the maintainer (from the project-manager synthesis)

1. **G-014 is a live broken instruction, not a missing feature** — a report filed via the documented platform channel is undeliverable *today*. Decide enable-vs-edit; it is the highest-integrity item in T-8.
2. **Any SBOM generated before G-033's annotation misrepresents the patched glib** — a correctness trap, not a nicety. T-10 encodes the ordering.
3. **G-009 rests on live platform configuration** (ruleset 18739705) — reverify before implementing T-9.
4. **The crypto core has the weakest auto-alerting in the repo** (major-version ignores + disabled security updates). T-6 is the cheapest partial mitigation; consider a security-advisory carve-out in the ignore list.
5. **The two corrected over-credits** (dead private-reporting channel; CI runs-but-does-not-gate) are already reflected in Section 1 of this report.
6. **(Third round) The Scorecard `VulnerabilitiesID` alert (#18) will not close by fixing anything** — 17 of its 18 advisories are documented accepted risks and the 18th becomes one via T-26; its OSV check does not honor cargo-audit ignores, so expect to dismiss it with a comment pointing at `audit.yml`'s removal gates (or live with a standing 0-score on that check until the GTK4 migration).
7. **(Third round) Do not treat the same-day scorecard PRs (#74/#75) as closing T-1's intent** — the forcing function only works if someone actually triages what it surfaces; 17 alerts are open and this report's todo mapping is the triage.

---

*End of report. Cite gaps as `G-NNN` — IDs are stable for the life of this report. Full evidence trail: `docs/audit/gap-analysis-source.md`.*
