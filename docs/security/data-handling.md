# Data handling and retention

A plain statement of what data src-control stores, where it lives, what leaves
the machine, and — most importantly — what can never be truly deleted. Written
as OSTIF-audit follow-up T-18 (G-021); the underlying design boundaries live in
[`docs/THREAT-MODEL.md`](../THREAT-MODEL.md).

## What the system stores

src-control's purpose is storing user-supplied repository content, which by
design may include **sensitive data as a first-class feature**: committed
secrets (envelope-encrypted), protected-path file content (encrypted per
recipient set), private branches (fully sealed — content, paths, messages, DAG
shape), plus ordinary plaintext repository content, commit metadata (author
string, timestamps, messages), and sealed agent-session transcripts.

The **project** (this repository and its maintainers) stores none of your data:
there is no telemetry, no phone-home, no hosted service. Every `.sc/` store
lives where you put it. Data leaves your machine only when *you* push/fetch to
a remote you chose, export to Git, or run `sc serve` for others.

## The retention model — read this before committing sensitive data

src-control is **content-addressed, append-only, and history-preserving**.
The consequences, stated plainly:

- **There is no true delete.** Objects written into history persist; every
  clone/fetch copies them. Removing a file at the tip does not remove it from
  history.
- **Rotation and revocation are not erasure.** `sc secret rotate`, `sc grant`
  revocation, and private-branch KEK rotation cut off *future* reads through
  the current registry. Anyone who already held a key, a wrap, or a fetched
  manifest keeps the ability to read what they already had. Real cutover of a
  leaked credential always means rotating the **underlying external
  credential** (the API key itself), not just src-control metadata.
- **Pre-P33 protected content stays equality-confirmable forever.** Content
  sealed before randomized encryption (P33) used convergent encryption; an
  observer of that ciphertext can forever confirm a guessed plaintext.
- **Escrow holders can read escrow-wrapped content** — including private
  branches before publish. See [`docs/agents/ACCESS.md`](../agents/ACCESS.md).
- **Injected secrets are not isolated.** `sc run` places decrypted secrets in
  a child-process environment: an authorized local context, observable by
  same-user processes.

## Personal data (PII) and erasure obligations

Commit metadata (names, emails, timestamps) is personal data in most regimes,
and users can commit arbitrary PII as content. Because history cannot be
erased, **src-control cannot honor a right-to-erasure request for data already
committed and propagated** — the honest mitigations are: don't commit PII you
may need to erase; use protected paths/private branches so future revocation at
least limits *new* readers; and treat any committed-then-regretted PII like a
leaked credential (rotate/invalidate the real-world referent where possible).
Operators of `sc serve` instances that accept other people's pushes take on
data-controller-like responsibility for what they retain; the project provides
no compliance tooling for that today.

## Current recommendation

Unchanged from [`SECURITY.md`](../../SECURITY.md): pre-1.0 and pre-audit — do
not commit real production secrets yet.
