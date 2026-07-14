# ADR-0045: Native desktop adapter and keyless read model

- **Status:** Accepted
- **Date:** 2026-07-14
- **Phase:** 35
- **Builds on:** ADR-0011 (native persistent repository), ADR-0014/0043
  (protected-content representation), ADR-0032 (signature status), ADR-0038
  (transcript metadata), ADR-0044 (private-branch opacity)

## Context

src-control needs a visual product surface that demonstrates its native
snapshot model without translating through Git or parsing CLI output. A desktop
renderer is useful for trees, diffs, and DAG interaction, but it creates a new
trust boundary: repository data crosses from Rust into an OS WebView. The first
slice must remain read-only and must not weaken the protection/private-branch
semantics already enforced by the repository crates.

## Decision

### Desktop placement

The Tauri v2 application lives under `apps/desktop/`. Its Rust crate is a
top-level adapter alongside `crates/cli` and calls `scl-repo`/`scl-core`
directly. Domain crates do not depend on Tauri or frontend packages.

### Typed IPC

The backend exposes only repository selection, reference history, snapshot
details, public file reads, and per-path first-parent comparison. Tree and
change-list responses contain metadata only; file and diff bodies are loaded
lazily after an explicit path selection and capped at 4 MiB per side. The chosen repository
root remains in Rust-managed state; later calls accept only native ids and
repo-relative paths. No generic filesystem, shell, URL, or object-store command
is exposed.

### Repository read model

The adapter converts native refs, snapshots, trees, signature status, and
transcript presence into immutable DTOs. The snapshot history walks every
parent so merge topology remains visible. Renderer-only tree/diff libraries are
fed by mapping these DTOs at the component boundary and remain replaceable.

### Confidentiality behavior

Phase 35 is keyless. Protected blob bytes are never read into an IPC response;
they become a `protected_locked` state. A private branch stops at its manifest
and becomes `private_opaque`; the adapter does not ask for or load an identity.
Transcript presence/count may cross IPC, but transcript ciphertext and bodies do
not. Private-key bytes have no IPC type.

### WebView boundary

The frontend is bundled with a deny-by-default production CSP and no remote
scripts; a distinct development CSP permits only the local Vite origin. Tauri
capabilities are minimal, and repository reads run on its blocking pool.
Repository text is rendered as text, not trusted HTML.
The WebView is treated as less trusted than the Rust backend even though both
run on the same machine.

## Consequences

- The app accurately represents native `.sc` history and security states.
- A compromised renderer can query only the repository the user selected and
  cannot turn IPC into arbitrary filesystem or shell access.
- Protected/private plaintext cannot enter frontend state in this phase.
- Oversized public blobs remain native objects but do not enter frontend state.
- Opening a query briefly acquires the repository's existing single-writer
  lock; a future long-lived read handle needs its own concurrency ADR.
- Mutation and authorized decryption remain future slices with separate threat
  modeling.

## Alternatives considered

- **Parse `sc --json` output.** Rejected: duplicates CLI presentation contracts,
  loses native typed errors, and makes the desktop a subprocess wrapper rather
  than an adapter.
- **Add UI read models to `scl-repo`.** Rejected: presentation concerns would
  leak into a domain crate and couple it to one product surface.
- **Expose the object store or filesystem over IPC.** Rejected: too broad to
  secure and makes ciphertext/source confusion easy.
- **Load an identity and decrypt in Phase 35.** Rejected: expands the key and
  plaintext trust boundary before the public browsing slice is proven.
- **Pure-Rust immediate-mode UI.** Rejected for this slice because mature web
  tree/diff rendering and Tauri's adapter boundary better fit the product need;
  it remains viable if eliminating the WebView later outweighs that benefit.
