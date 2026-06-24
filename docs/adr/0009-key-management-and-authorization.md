# ADR-0009: Recipient-based key management and authorization

- **Status:** Accepted
- **Date:** 2026-06-24
- **Phase:** 2

## Context

ADR-0008 wraps each secret's DEK "per authorized recipient." That presumes an
identity and authorization model: what a recipient *is*, how DEKs are wrapped to
them, how access is granted and revoked, and what "authorized execution context"
means in practice. This ADR defines that model.

## Decision

**Identity = an asymmetric keypair.** A recipient is identified by an **X25519**
public key; its `recipient_id` is a stable fingerprint of that public key. DEK
wrapping uses X25519 key agreement to derive a wrapping key, which encrypts the
DEK under an AEAD (sealed-box style). Holding the corresponding **private key**
is the sole proof of authorization — there is no separate ACL service to trust
or keep in sync.

- **Recipients** can be humans (developer keys), machines (CI runner keys), or
  environment identities (a "production" key). A secret is wrapped for a chosen
  set of recipients at `sc secret add` time.
- **Granting access** = wrapping the existing DEK for an added public key and
  storing the new wrapped-key entry. **Revoking access** = removing a recipient's
  wrapped-key entry (and, for true secrecy of an already-exposed value, rotating
  the secret — see ADR-0008 consequences).
- **Authorized execution context** = a process that holds an authorized private
  key (supplied out-of-band: an agent/operator key, a CI secret, or an HSM/KMS-
  backed key). Decryption-on-checkout uses it to unwrap the DEK in memory only.
- Private keys are **never** committed. Only public keys and wrapped DEKs live in
  repo state.

## Consequences

- Authorization is decentralized and verifiable from repo content alone: the set
  of `recipient_id`s on a secret *is* the access list; no external ACL to drift.
- Multi-recipient is native: a secret readable by "me + CI + prod" is three
  wrapped DEKs over one ciphertext.
- Recovery/rotation policy must be defined: losing all authorized private keys
  for a secret means the value is unrecoverable (by design). A "break-glass"
  recipient key held in escrow is the recommended mitigation, documented when the
  feature ships.
- Key distribution and trust (how you learn a teammate's real public key) is a
  classic PKI problem; the MVP will start with explicit key files / a checked-in
  recipients list and can integrate org SSO/KMS later.
- A `KeyProvider` abstraction should sit behind decryption so private keys can
  come from a file, an env var, an agent, or a cloud KMS without changing call
  sites.

## Alternatives considered

- **Password/passphrase-derived keys (Argon2).** Useful as an *optional* recipient
  type (encrypt-to-passphrase) but poor as the primary identity: shared, phishable,
  and hard to revoke per-user. May be added alongside X25519, not instead of it.
- **Central KMS as the only authority.** Strong key custody but reintroduces an
  always-online external dependency and undercuts "authorization is in the repo."
  Better modeled as one recipient type (a KMS-backed key) within this scheme.
- **RSA recipients.** Larger keys/ciphertext and more footguns than X25519 for no
  benefit here.
- **Group keys (one shared key per team).** Simple but revocation requires
  re-keying the whole group; per-recipient wrapping avoids that.
