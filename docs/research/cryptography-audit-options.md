# Independent cryptography audit options

Research date: 2026-07-18

## Recommendation

Send the same request for proposal to **NCC Group Cryptography Services**,
**Cure53**, and **Trail of Bits**. Select the named reviewers and proposed work
plan, not the firm name alone. **Least Authority** and **Quarkslab** are strong
additional bidders. For sponsored open-source work, apply to **OSTIF** first.

This should be commissioned as a protocol/design review plus implementation and
integration review, not a penetration test and not a review of `scl-crypto`
alone. The primitives are concentrated in roughly 1,500 lines in
`crates/crypto`, but their security properties depend on serialization,
content-addressing, recipient policy, repository history, merging, transports,
and filesystem/process boundaries elsewhere in the project.

## Shortlist

### NCC Group Cryptography Services — strongest direct cryptography match

NCC has a dedicated Cryptography Services practice and published a Rust
cryptography review covering three libraries, delivered by two consultants in
40 person-days including retesting. It has also reviewed RustCrypto AEAD
implementations. Ask for reviewers with current Rust, X25519/envelope-
encryption, protocol-composition, and storage-system experience.

- [Entropy/Rust cryptography review](https://www.nccgroup.com/research/public-report-entropyrust-cryptography-review/)
- [RustCrypto AEAD review](https://www.nccgroup.com/research/public-report-rustcrypto-aesgcm-and-chacha20pluspoly1305-implementation-review/)
- [Cryptography and encryption assurance](https://www.nccgroup.com/technical-assurance/cryptography-encryption/)

### Cure53 — strongest directly comparable European portfolio

Cure53 explicitly audits cryptographic algorithms, implementations, key
management, protocols, and libraries. Its public work includes RustCrypto
`crypto_secretbox`/`crypto_box`, rustls, the NIP-44 specification plus its Rust
implementation, and the Rust/Tauri Nym system. That is unusually close to this
project's mix of Rust cryptography, TLS, protocol design, and desktop surface.
Business enquiries: `hello@cure53.de`.

- [Services, reports, and contact](https://cure53.de/)
- [Rust cryptography libraries report](https://cure53.de/pentest-report_rust-libs_2022.pdf)
- [rustls report](https://cure53.de/pentest-report_rustls.pdf)
- [NIP-44 specification and implementations report](https://cure53.de/audit-report_nip44-implementations.pdf)

### Trail of Bits — strongest multidisciplinary engagement

Trail of Bits combines cryptography, application security, and systems review.
Its standard assurance engagement includes technical onboarding, continuous
access to reviewers, a report/readout, optional fix review, proof-of-concept
artifacts, static-analysis rules, and fuzzing harnesses. This is attractive if
the scope includes the entire repository boundary rather than cryptography
alone. Request a quote or use its complimentary technical office hours to test
scope fit.

- [Software Assurance process](https://trailofbits.com/services/software-assurance)
- [Rust cryptography engineering capability](https://trailofbits.com/services/security-engineering/)
- [Rust DKLs23 review case study](https://blog.trailofbits.com/2025/06/10/what-we-learned-reviewing-one-of-the-first-dkls23-libraries-from-silence-laboratories/)

### Least Authority — strong privacy/distributed-systems alternative

Least Authority explicitly lists Rust and reviews cryptographic protocols and
distributed-system architecture. Its process includes a tailored quote,
remediation support, verification, and an optionally public final report.
Contact: `consulting@leastauthority.com`.

- [Security consulting, process, and contact](https://leastauthority.com/security-consulting/)
- [Rust audit portfolio](https://leastauthority.com/blog/tag/rust/)
- [Matrix vodozemac Rust cryptography report](https://leastauthority.com/static/publications/LeastAuthority-Matrix_vodozemac_Final_Audit_Report.pdf)

### Quarkslab — specialist low-level/side-channel alternative

Quarkslab's Dalek audit covered `curve25519-dalek`, X25519, Ed25519,
Bulletproofs, generated assembly, and constant-time behavior. It is a strong
candidate if the engagement emphasizes low-level implementation and side
channels, though this project's larger risk is likely protocol composition and
repository integration because it uses established primitive libraries.

- [Dalek libraries audit](https://blog.quarkslab.com/security-audit-of-dalek-libraries.html)
- [Quarkslab services](https://www.quarkslab.com/)

### Other credible bidder

Kudelski Security has published Rust multi-party ECDSA reviews and provides a
dedicated cryptography-audit scoping questionnaire. It is credible, although
the public examples are less directly similar to an encrypted version-control
system than the options above.

- [KZen Rust MPC report](https://research.kudelskisecurity.com/wp-content/uploads/2019/10/kzen_mpecdsa_audit_20191022.pdf)
- [Cryptography audit questionnaire](https://resources.kudelskisecurity.com/crypto-audit-questionnaire)

## Sponsored route

OSTIF is the clearest funding/coordination route for an open-source project. It
helps define scope, solicits bids from independent review teams, coordinates the
audit and remediation, and publishes the report after fixes. Acceptance and
funding are not guaranteed.

- [OSTIF: Get an Audit](https://ostif.org/get-an-audit/)

Alpha-Omega supports security work on critical open-source projects, but its
selection model favors already critical/widely used infrastructure, so it is a
less likely near-term route for a pre-1.0 project. NLnet's NGI Zero Commons Fund
explicitly allowed security audits, but its final call closed on 2026-06-01.

- [OpenSSF Alpha-Omega](https://openssf.org/community/alpha-omega/)
- [NGI Zero Commons Fund status](https://nlnet.nl/commonsfund/)

## Proposed work packages

1. **Threat model and protocol design:** security goals and leakage; envelope
   construction; X25519/HKDF binding; domain separation; key hierarchy;
   revocation/rotation/history semantics; randomized versus legacy convergent
   content; private-branch rollback/freshness; signature and TLS trust models.
2. **Crypto implementation:** `crates/crypto`, `crates/tlsio`, canonical
   encodings, malformed-input behavior, entropy/nonces, secret memory handling,
   dependency assumptions, unsafe code, and side channels.
3. **Repository integration:** secret/protected/private-branch/transcript and
   signature flows; merges/replay/rewrap; import/export; clone/fetch/push;
   authorization; caches; identity-file permissions; scanner crossings; hostile
   objects and wire data.
4. **Adversarial testing:** fuzz targets and property tests retained by the
   project, cross-implementation/test vectors where possible, rollback and
   recipient-confusion tests, corruption and resource-exhaustion cases.
5. **Funded retest:** verify every remediation against a fixed commit and issue
   a publishable final report.

Published comparable reviews span roughly 10 person-days for a focused
specification/multi-implementation review, 30 days for rustls or Dalek-sized
work, and 40 person-days for several Rust cryptography libraries. No shortlisted
firm publishes a monetary rate card. For this project, ask bidders to price a
staged review and state coverage per work package; do not treat person-day
comparables as fee quotes.

## Pre-audit cleanup

- Freeze a commit/tag and pause crypto-adjacent feature work during review.
- Reconcile `SECURITY.md` with the current P32 TLS and P33 randomized-protection
  design before soliciting bids; it currently contains stale pre-P32/P33 claims.
- Give reviewers the prior six-finding security review and all remediation, but
  describe this engagement accurately as the first independent cryptography
  audit.
- Produce one compact protocol specification with algorithms, formats, AAD and
  signature domains, key lifecycle/state transitions, invariants, and accepted
  leakage. ADRs remain supporting rationale.
- Resolve or explicitly mark every known crypto/security follow-on in
  `ROADMAP.md`; paying an auditor to rediscover an acknowledged issue wastes
  coverage.
- Require the proposal to name the actual reviewers, disclose conflicts,
  include remediation support/retest, and grant the project publication rights.

