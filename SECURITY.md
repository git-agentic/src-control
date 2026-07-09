# Security Policy

## ⚠️ Pre-1.0, pre-audit — do not trust production secrets to it yet

src-control is a **pre-1.0 (`0.1.0`)** system whose cryptography has **not had an
independent security audit**. It implements real cryptographic features —
committed-secret envelope encryption, convergent-encryption protected paths, and
Ed25519 signed provenance — but they are MVP implementations reviewed only by the
project's own process. **Do not commit real production secrets to a src-control
repository yet**, and do not rely on it as your only line of defense for
confidential data.

Known, deliberate boundaries you should understand before trusting anything to it
are consolidated in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). In brief:
convergent encryption for protected paths is **equality-confirmable** by design;
`sc serve --http` is **plaintext (no TLS)** and its bearer tokens cross the wire in
the clear; committed secrets injected by `sc run` live in an **authorized local
process context, not strong isolation**; and rotation/revocation cut off *future*
reads through the current registry but cannot erase ciphertext already in history.

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
  on this repository.

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

Reports about the documented, deliberate boundaries above are welcome as
hardening suggestions, but they are known limitations rather than
vulnerabilities.
