# src-control — Threat model & security boundaries

This document consolidates, in one place, the **deliberate security boundaries**
of src-control's cryptographic features — the things it does *not* defend against
by design. They are drawn from the per-phase ADRs (linked below); this page
exists so a newcomer evaluating whether to trust real data to the system does not
have to read 44 ADRs to find the caveats.

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

## Protected paths (`sc protect`) — ADR-0014/0026/0027/0043

- **Defends:** read-confidentiality of designated file content for a chosen
  recipient set; an unauthorized clone gets ciphertext it cannot read.
- **Equality-confirmation oracle — closed for new content (P33, ADR-0043);
  pre-P33 convergent ciphertext in history stays confirmable forever
  (rotation ≠ erasure, ADR-0019).** Protected paths *used to*
  use *convergent encryption* (DEK and nonce derive from `BLAKE3(plaintext)`),
  so identical plaintext dedups to identical ciphertext and an observer could
  confirm that two protected files are identical, or that a protected file
  matches a **guessed** plaintext. As of P33, **all content sealed from this
  phase on uses a fresh random DEK + random nonce** — two seals of the same
  plaintext yield different ciphertext ids, closing the oracle. Convergent
  ciphertext already written into history stays readable (dual-read) and
  remains equality-confirmable **forever** to anyone holding a clone — this is
  the same rotation ≠ erasure boundary ADR-0019 already names for secrets:
  content addressing means the old convergent object stays reachable in
  history regardless of what happens at the tip. `sc rewrap` re-seals a
  still-convergent blob randomized **at the live tip**, which stops that
  plaintext's convergent form from propagating into *future* snapshots built
  on top — it does not erase the historical convergent object, which any clone
  that already fetched it (or fetches it later) can still equality-confirm
  against. Real cutover of guessable content means changing the content (or
  underlying credential) itself, not just re-sealing at the tip. Low-entropy
  secrets (API keys, `.env`) still belong in `sc secret`, not `sc protect` —
  `sc protect` prints a nudge to that effect, and the P28 rationale is
  unchanged (governed secret lifecycle beats a protected file even with
  randomized sealing).
- **Revocation is durable but not retroactive:** `sc revoke` survives merges of
  pre-revoke branches (revocation tombstones, ADR-0026), so a revoked recipient
  never seals a *fresh* DEK again. But a recipient who already held a wrap can
  still decrypt the ciphertext sealed *before* the revoke — cryptographic cutover
  is rotation (`sc rewrap` on the live tip), not revoke, and history keeps the old
  wraps regardless.

## Private branches (`sc branch --private` / `sc branch publish`) — ADR-0044

- **Defends:** the full content of a private branch — file bytes, **file
  paths**, commit messages, authors, timestamps, and inner DAG shape — against
  any party lacking a recipient (or escrow) key. Every object a private commit
  introduces is individually sealed (`Object::Sealed`, fresh random DEK per
  object) under a per-branch KEK; the ref points at a manifest whose only
  plaintext is structural (a flat sealed-object id list + the public fork
  point). An unauthorized clone, the hosting server, and every transport
  (plaintext `sc+http://` included) see **ciphertext only** — verified by
  `demo/run_private_branch_demo.sh` and by the wire-pack decode test in
  `crates/repo/src/private.rs` (the honest structural check a shell grep
  cannot make: it decodes every non-sealed object off the wire and asserts no
  private plaintext).
- **Leaks by design (accepted metadata):** a private branch's **existence and
  name** (name blandly — `hotfix-CVE-1234` in a ref itself discloses), the
  sealed-object **count and sizes**, closure **growth over time** (commit
  activity is observable as count deltas), the **recipient ids** (in the
  manifest's KEK wraps), the **public fork point**, and **which public commits
  were merged in** (both plaintext reachability anchors in the manifest — the
  fork point plus the tips of any public branch merged in to keep the embargo
  current, so the sealed trees' references stay transferable). No content,
  path, or message is among these.
- **Revoke is a KEK rotation, not erasure:** `sc branch revoke` mints a fresh
  KEK, re-encrypts the index, and rewraps for the remaining recipients — with
  zero content plaintext written and zero sealed-object id churn. A revoked
  recipient who **already fetched** the branch keeps the old manifest + old KEK
  and can decrypt everything sealed *before* the revoke, forever (the same
  rotation ≠ erasure boundary ADR-0019 names for secrets — content addressing
  keeps the old manifest reachable in any clone that has it). The rotation
  guarantees they can read nothing sealed *after*. Real cutover of already-
  disclosed content also means rotating the underlying credential.
- **Escrow holders can read pre-publish:** the branch KEK is wrapped to the
  configured escrow set at creation (and re-wrapped on every membership
  change), so break-glass holders can open an embargoed branch — the standing
  meaning of escrow, applied consistently.
- **Publish makes intermediate commit messages public** and gives every
  published commit a **new snapshot id** (a sealed id is BLAKE3(ciphertext), a
  public id is BLAKE3(plaintext) — equal ids would be the very oracle P33
  closed), so **published commits start unsigned** (re-sign with `sc sign`).
  Publish re-runs the P5 secret scanner over all decrypted content **before**
  writing any public object, so a secret committed under seal cannot sail into
  plaintext history at release.
- **Does NOT defend:** a malicious *recipient* (any key-holder can read,
  commit, grant, or publish); the git bridge carries private branches **not at
  all** (export/push refuse unconditionally — `--include-encrypted` does not
  apply, ADR-0044 §7); and integrating a private branch *into* a public one is
  refused everywhere except `sc branch publish` — the one loudly-named,
  atomic, scanner-gated crossing.

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

## Network transport (`sc serve --http` / `sc+http(s)://` / `ssh://`) — ADR-0022/0036/0040/0041/0042

- **Two confidential transports now ship: `sc+https://` (P32, ADR-0042) and
  `ssh://` (P12, ADR-0022).** `ssh://` has been fully confidential since
  Phase 12 — it delegates the entire channel to the user's `ssh`, inheriting
  whatever SSH's own transport security and host-key trust already provide;
  it was never plaintext and needed no separate TLS story. `sc+https://` adds
  the same property for operators without ssh reach: a bearer token (P29) and
  all repository traffic are encrypted end to end, at both the server and the
  client leg, with no reverse proxy required.
- **`sc+https://` trust model is accept-new TOFU, stated plainly (the SSH
  `known_hosts` trade).** The server auto-mints a self-signed identity
  (`.sc/serve-tls/`) or loads an operator-supplied PEM cert; the client pins
  `SHA-256(SPKI)` on first connect into `~/.config/sc/known_hosts`
  (`SC_HTTPS_KNOWN_HOSTS` overrides the path). **The first connection to any
  host is unverified by construction** — an active MITM present on that
  specific first connection is not detected. Every subsequent connection
  compares against the stored pin and hard-fails on any mismatch, never
  silently proceeding and never prompting to accept a changed key.
  `SC_HTTPS_FINGERPRINT` lets an operator (e.g. CI) pre-pin out-of-band
  instead of trusting the first connection; `SC_HTTPS_STRICT=1` refuses to
  connect to any host with no existing pin, closing the accept-new window
  entirely for operators who need it. Trust is **pin-only in v1** —
  certificate names and validity periods are deliberately ignored, and
  CA-path validation as an additional trust option is deferred (see
  `ROADMAP.md`). The TLS handshake signature is still verified even though
  names/validity are not, so a captured certificate replayed without its
  matching private key is rejected regardless of pin state.
- **`sc+http://` (plaintext) still exists, and its boundary is now narrower
  and clearer: it applies only to loopback or explicitly `--allow-public`
  deployments.** A public (non-loopback) plaintext deployment protected by
  bearer tokens *alone* is no longer a supported configuration — as of P32,
  `--tls` is required alongside ≥1 token to justify a non-loopback bind (the
  P29 gate is narrowed; a token guarding only a plaintext channel was always
  a weaker guarantee than the earlier wording implied). A loopback bind with
  no tokens configured stays unauthenticated by design (local-dev
  ergonomics, unchanged since P29); `--allow-public` with no tokens is still
  a sanctioned foot-gun — a deliberately open, unauthenticated, plaintext
  server, for the operator who explicitly asked for it.
  **Residual plaintext-token exposure, stated plainly:** a public bind
  justified by `--read-only` or `--allow-public` *with* tokens configured
  still requires the bearer on every connection — the P32 gate closes only
  the tokens-ALONE justification, not plaintext token use in general — so
  those tokens still cross the wire in cleartext on such a deployment. Use
  `sc+https://` (or `ssh://`) instead of `sc+http://` whenever a public bind
  needs its bearer tokens to stay confidential in transit.
- **Reverse-proxy guidance, corrected to cover both legs.** Prior guidance
  ("front with a TLS reverse proxy") was incomplete: a server-side proxy
  terminates TLS toward clients that speak TLS, but before P32 the `sc`
  client itself spoke only plaintext TCP, so a server-side proxy alone
  encrypted nothing end-to-end. Now that `sc+https://` and `ssh://` both
  exist, the reverse-proxy path is a **fallback for operators who want their
  existing proxy infrastructure in front of `sc`**, not the primary
  confidentiality answer. If used, both legs need care:
  - **Server side — raw-TCP/stream-mode TLS termination, never HTTP mode.**
    The post-opening protocol is not HTTP, so an HTTP-mode reverse proxy will
    not tunnel it. Use nginx `stream {}` + `ngx_stream_ssl_module` (note:
    neither the `stream` block nor its ssl module is built into a default
    nginx — check `nginx -V`; and `ssl_preread` is routing-only, it does
    **not** terminate TLS), or HAProxy `mode tcp` with `bind :<port> ssl crt
    <pem>`, or stunnel's server mode (`accept`/`connect`/`cert`). Forward
    decrypted bytes to a **loopback-bound** `sc serve --http 127.0.0.1:…`
    and keep bearer tokens configured — the proxy→`sc serve` hop is
    plaintext loopback, and the token is still the authorization mechanism
    on that hop.
  - **Client side — the leg the old guidance omitted.** The unmodified `sc`
    client cannot itself speak TLS to a plaintext `sc+http://` remote it
    thinks it's talking to over an encrypted channel; a client-side tunnel
    (stunnel's client mode, `client = yes`, or `ssh -L`) is required to give
    that plaintext client an encrypted leg to the proxy. **Simplest fix:
    skip both legs of this section entirely and use `sc+https://` or
    `ssh://` directly** — they exist now specifically so this two-legged
    proxy dance is no longer the only option.
  - See `docs/research/tls-options-sc-http.md` §B for the full comparison
    (nginx/HAProxy/stunnel capabilities, Caddy's non-bundled layer-4 caveat)
    that this guidance is drawn from.
- **Minor pre-auth information leak (both `sc+http://` and `sc+https://`):**
  a `404` (no repo) is written before the auth gate, so an unauthenticated
  client can distinguish "a repo is served here" (`401`) from "no repo"
  (`404`). No content is exposed.
- **Not proxy/CDN-safe** (raw post-opening protocol, both plaintext and TLS
  variants) — this remains open, deferred in [`ROADMAP.md`](../ROADMAP.md).
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
