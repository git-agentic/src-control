# Security Policy

## ⚠️ Pre-1.0, pre-audit — do not trust production secrets to it yet

src-control is a **pre-1.0 (`0.1.0`)** system whose cryptography has **not had an
independent security audit**. It implements real cryptographic features —
committed-secret envelope encryption, encrypted protected paths, private
branches, Ed25519 signed provenance, and in-binary TLS — but they are MVP
implementations reviewed only by the project's own process. **Do not commit real
production secrets to a src-control repository yet**, and do not rely on it as
your only line of defense for confidential data.

Known, deliberate boundaries you should understand before trusting anything to
it are consolidated in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). In brief:

- **Protected paths use randomized sealing since P33** (fresh random DEK +
  nonce per seal). Content sealed *before* P33 used convergent encryption and
  remains **equality-confirmable forever** — rotation cannot erase ciphertext
  already in history.
- **Two confidential transports ship:** `sc+https://` (in-binary TLS with
  accept-new TOFU pinning; the *first* connection to a host is unverified by
  construction, and `SC_HTTPS_FINGERPRINT` / `SC_HTTPS_STRICT=1` close that
  window) and `ssh://`. Plain `sc serve --http` remains **plaintext** and its
  bearer tokens cross the wire in the clear — use it only on loopback or behind
  the documented stream-mode proxy setup; prefer `sc+https://` for any public
  bind.
- Committed secrets injected by `sc run` live in an **authorized local process
  context, not strong isolation** — same-user processes can observe the child
  environment.
- **Rotation/revocation ≠ erasure.** They cut off *future* reads through the
  current registry but cannot erase ciphertext already in history and copied to
  other clones; real cutover of a leaked credential always means rotating the
  underlying external credential too.

## Supported Versions

The repository is pre-release. Only `main` receives security fixes today; a
supported-release table will appear once a tagged `0.x`/`1.0` line exists.

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |
| tagged  | not yet cut        |

## Reporting a Vulnerability

Please **do not** open public GitHub issues for security vulnerabilities. Report
them privately, either by:

- **Email** to **toni@git-agentic.com**, or
- GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
  on this repository (enabled).

Include as much of the following as is available:

- A description of the vulnerability and the impact you believe it has.
- Steps to reproduce, ideally with a minimal proof-of-concept.
- The commit hash affected.
- Any suggested mitigations.

You can expect:

- An acknowledgement within **3 business days** of receipt.
- A status update within **7 business days** confirming whether the report is
  accepted, asking for more information, or explaining why it's out of scope
  (e.g. a documented boundary in `docs/THREAT-MODEL.md`).
- A coordinated-disclosure timeline once a fix is identified; the default is
  **90 days** from accepted report to public disclosure, shorter if a fix lands
  sooner.

In return, we ask that you **hold the report in confidence** — please do not
share it with third parties or disclose it publicly until a fix has shipped or
the agreed disclosure date passes, whichever comes first. We will credit you in
the disclosure unless you prefer otherwise.

## Safe harbor for good-faith research

We will not pursue or support legal action against you for good-faith,
non-destructive security research on this project conducted within this policy:
testing against your own clones and deployments, no access to or exfiltration of
other people's data, no degradation of infrastructure you do not own, and
private reporting through the channels above. This is a statement of intent by
the maintainers, not a legal opinion; if you are unsure whether something is in
scope, ask first via the reporting channels.

## Bug bounty

There is **no bug bounty program** at this time — no monetary rewards are
offered. Reports are credited in the disclosure and in release notes.

Reports about the documented, deliberate boundaries above are welcome as
hardening suggestions, but they are known limitations rather than
vulnerabilities.
