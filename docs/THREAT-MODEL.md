# src-control — Threat model & security boundaries

This document consolidates, in one place, the **deliberate security boundaries**
of src-control's cryptographic features — the things it does *not* defend against
by design. They are drawn from the per-phase ADRs (linked below); this page
exists so a newcomer evaluating whether to trust real data to the system does not
have to read 40 ADRs to find the caveats.

> **Status: pre-1.0, not independently audited.** These are MVP implementations
> reviewed by the project's own process only. Do not commit production secrets to
> a src-control repo yet. See [`SECURITY.md`](../SECURITY.md).

A recurring principle underlies most boundaries below: src-control is
**content-addressed and history-preserving**. Rotation, revocation, and deletion
cut off *future* reads through the current registry; they cannot erase ciphertext
or objects already written into history and copied to other clones. Real cutover
of a leaked credential always means rotating the underlying external credential
too, not just the src-control-side metadata.

## Committed secrets (`sc secret` / `sc run`) — ADR-0008/0009/0010/0019

- **Defends:** an unauthorized clone (no recipient private key) receives the
  secret object intact but cannot unwrap any DEK, so the value stays ciphertext —
  confidential at rest and in transit, no separate vault.
- **Does NOT defend:** the decrypted value once injected. `sc run` injects secrets
  as **child-process environment variables** — an *authorized local process
  context, NOT strong isolation*. Same-user processes, crash dumps, and shell
  wrappers can observe the plaintext through the child environment; this is
  fundamental to env-var injection. The parent's intermediate buffer is zeroized
  (best-effort), the child copy is not.
- **Re-affirmed (map ticket #31): fd/stdin injection stays deferred.** The
  security claim for a non-env injection mode is mostly illusory against the
  named adversary — a same-user attacker who can read the identity key file
  and `.sc/` directly decrypts everything regardless of injection mechanism;
  what fd/stdin would actually remove is *accidental* propagation (env dumps,
  inheritance by grandchildren), which is hygiene, not attack surface. Env
  stays the default contract for `sc run`, `sc work --with-secrets`, and `sc
  ws run --with-secrets` alike. Revisit triggers: real committed-secret use in
  agent sessions, or an observed env-leak incident class (agents dumping env
  into logs or committed files) — at which point an additive fd-pipe opt-in
  mode is the presumptive shape, since deferring an *additional* mode carries
  no lock-in cost.
- **Rotation ≠ erasure:** `sc secret rotate` re-seals under a fresh DEK and cuts
  off future reads through the current registry, but the old ciphertext object
  remains reachable and decryptable by anyone who kept the old DEK. `sc secret
  revoke` is metadata-only. Real security requires rotating the underlying
  external credential.

## Protected paths (`sc protect`) — ADR-0014/0026/0027

- **Defends:** read-confidentiality of designated file content for a chosen
  recipient set; an unauthorized clone gets ciphertext it cannot read.
- **Does NOT defend — equality is confirmable:** protected paths use *convergent
  encryption* (DEK and nonce derive from `BLAKE3(plaintext)`), so identical
  plaintext dedups to identical ciphertext. An observer of the ciphertext can
  therefore confirm that two protected files are identical, or that a protected
  file matches a **guessed** plaintext. This is a deliberate tradeoff for dedup,
  documented in ADR-0014. Low-entropy secrets (API keys, `.env`) belong in
  `sc secret`, not `sc protect` — `sc protect` prints a nudge to that effect.
- **Revocation is durable but not retroactive:** `sc revoke` survives merges of
  pre-revoke branches (revocation tombstones, ADR-0026), so a revoked recipient
  never seals a *fresh* DEK again. But a recipient who already held a wrap can
  still decrypt the ciphertext sealed *before* the revoke — cryptographic cutover
  is rotation (`sc rewrap` on the live tip), not revoke, and history keeps the old
  wraps regardless.

## Signed commits & provenance (`sc commit --sign` / `sc verify`) — ADR-0032

- **Defends:** history rewriting (an `amend`/`rebase`/`merge`-attack in a clone or
  on a remote is caught by `sc verify --require`, since a rewrite produces a new,
  unsigned snapshot id) and attribution disputes (a signature binds a specific
  identity to a snapshot).
- **Does NOT defend:** a *trusted signer acting maliciously*; the code quality or
  truthfulness of what was signed; or **replay** of a legitimately-signed snapshot
  into a different branch position (a signature binds identity to a snapshot *id*,
  not to a branch position). `amend`/`rebase`/`merge` results start **unsigned by
  design** — a new snapshot id is a new claim that must be re-signed.
- **Re-affirmed and sharpened (map ticket #32): replay is ref binding only.** A
  snapshot's parents are hashed into its id, so a signature over the id already
  binds identity to the snapshot **and its entire ancestry** — a signed snapshot
  cannot be grafted under different parents without voiding the signature.
  "Replayed elsewhere in history" overstates the residue; the accurate claim is
  narrower: a legitimately-signed snapshot is **replayable to a ref tip within
  its own history** — nothing stops a hostile remote from pointing a branch name
  at an older or side-branch signed snapshot (a rollback/ref-swap), the same gap
  git addresses with signed pushes or gittuf-class ref metadata. Deferred: a
  gittuf-shaped signed ref attestation (freshness/monotonicity semantics,
  verified at fetch/clone) is its own trust-model effort, not a corner of an
  unrelated map. Revisit triggers: the first real multi-writer or hosted `sc
  serve` deployment, or hosting sc repos on untrusted infrastructure.

## Agent session transcripts (`sc transcript`) — ADR-0038

- **Defends:** transcript disclosure to unauthorized clones (the body is *always*
  sealed — a keyless clone gets ciphertext only); loss of agent context at harvest;
  transcripts outliving the history they describe (gc-coupled index).
- **Does NOT defend:** a *fabricated* transcript attached by an authorized writer
  (attachment is a claim; opt-in signing upgrades it to an attested claim, but an
  unsigned transcript is still just a claim); secrets an agent echoed into a
  transcript remaining readable to *authorized* transcript recipients (the P5
  scanner warns at attach time but never blocks; rotation of the underlying secret
  remedies).

## Network transport (`sc serve --http` / `sc+http://`) — ADR-0036/0040/0041

- **No TLS.** `sc serve --http` is **plaintext**. When bearer-token auth is
  configured, the token crosses the wire in the clear — a public deployment MUST
  be fronted by a TLS reverse proxy. `sc+https://` is deferred.
- **Auth is opt-in.** With no tokens configured, a loopback bind is unauthenticated
  by design (local-dev ergonomics); a non-loopback bind is **fail-closed** (refused
  unless `--read-only`, `--allow-public`, or ≥1 configured token). `--allow-public`
  with no tokens is a sanctioned foot-gun: a deliberately open server.
- **Minor pre-auth information leak:** a `404` (no repo) is written before the auth
  gate, so an unauthenticated client can distinguish "a repo is served here" (`401`)
  from "no repo" (`404`). No content is exposed.
- **Not proxy/CDN-safe** (raw post-opening protocol) — this remains open, deferred
  in [`ROADMAP.md`](../ROADMAP.md).
- **Listener resource bounds — closed by P31 (ADR-0041).** The three operational-
  hardening items this section used to track as open are now closed, plus a
  fourth gap P31's own research pass first named:
  - **Connection exhaustion:** an atomic connection counter enforces
    `--max-connections` (default 32, matching `git-daemon`); at the limit a new
    connection is accepted, immediately given a busy status at the pre-handshake
    opening seam, and closed — no queuing, no unbounded thread spawn.
  - **Idle/stalled-peer exhaustion:** `--timeout` (default 300s, 0 disables) sets
    read *and* write timeouts on the session socket for its whole lifetime — not
    just the opening's original 30s, which used to be cleared once the wire
    handoff began. A trip is connection-fatal (frame desync precludes recovery);
    the spooled temp pack is guard-cleaned on the resulting unwind.
  - **Accept-loop hot-spin under fd exhaustion:** a hardcoded exponential backoff
    (5ms doubling to a 1s cap, reset on the next successful accept — Go
    `net/http`'s shape) paces retries around `EMFILE`/`ENFILE` instead of
    busy-looping.
  - **Aggregate pack-spool exhaustion (named and closed together, P31):** this
    item was never listed here or in ADR-0036 before P31's research pass found
    it. The incoming-pack spool used no aggregate size bound — only ADR-0039's
    per-frame/per-record caps applied — so a single oversized or endless pack
    could exhaust server disk on **either** transport. `--max-pack-size`
    (default 16 GiB, 0 = unlimited, floor 256 MiB = `MAX_OBJECT_SIZE`) now
    counts the running total and aborts mid-stream past the cap. This includes
    the **read-only drain path**: the pre-`EC_READONLY` drain that keeps a
    connection in sync when a read-only-scoped client streams a pack the server
    is about to reject was itself unbounded — an `ro`-token client could still
    write arbitrary bytes to `.sc/tmp` before being told no. It is now capped at
    ~8 MiB (`RO_DRAIN_CAP`): an honest small misconfigured push still gets the
    clean typed `EC_READONLY` error, while a larger bulk spool is dropped
    mid-send instead of fully drained to disk.
  - **Not closed by P31:** per-IP/per-token sub-limiting (a distributed
    many-connections-from-many-sources attack below the per-listener cap is
    unaddressed), and a legitimate transfer slower than a true 300s zero-byte
    stall is unaffected by `--timeout`, but an operator on an unusually slow
    network must raise it explicitly. See ADR-0041 for the full decision,
    including rejected alternatives.
- The ssh:// transport delegates authentication entirely to ssh (ADR-0022);
  `--max-pack-size` is the one P31 bound that also applies to `--stdio`.

## Untrusted-input hardening (DoS) — ADR-0039

- A single `MAX_OBJECT_SIZE` (256 MiB) caps every untrusted length: wire frames,
  pack-record compressed length, the zstd *decompressed* output (decompression-bomb
  guard), and object-decode collection counts. **Accepted boundary:** the cap is a
  *transfer-path* guard — a locally-committed blob larger than 256 MiB commits fine
  but cannot then be transferred; and the wire frame-length header can still
  allocate up to the cap before a chunk boundary is enforced (a deferred
  hostile-peer hardening item).

## Reporting

Security reports go to **toni@git-agentic.com** or GitHub private vulnerability
reporting — see [`SECURITY.md`](../SECURITY.md). Reports about the deliberate
boundaries above are welcome as hardening suggestions, but they are known
limitations, not vulnerabilities.
