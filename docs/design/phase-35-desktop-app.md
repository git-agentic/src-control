# Phase 35 desktop application design

## Objective

Phase 35 proves that src-control's native object model can power a polished,
read-only desktop browser. The app opens an existing `.sc` repository, shows
local and remote-tracking refs, makes the snapshot DAG and provenance metadata
central, and browses public file content and first-parent comparisons. It is not
a Git client and it exposes no mutation surface.

## Placement

The app lives under `apps/desktop/`. Its Tauri Rust crate is a top-level adapter
alongside `crates/cli`: it depends on `scl-repo` and `scl-core`, while no domain
crate depends on Tauri, TypeScript, or presentation packages.

```text
apps/desktop/
├── src/                       TypeScript/React presentation
│   ├── api.ts                 typed IPC wrappers
│   ├── model.ts               renderer-side DTO declarations
│   ├── app/                   selection and loading state
│   └── components/            refs, DAG, inspector, tree, file/diff views
└── src-tauri/
    ├── src/commands.rs        narrow Tauri commands
    └── src/read_model.rs      native repository read-model adapter
```

The adapter opens the repository only for the duration of a query. This reuses
the existing `Repo` lock and avoids inventing a second concurrency contract.
Phase 35 never moves a ref or writes an object.

## Typed IPC boundary

The renderer can invoke only five repository operations:

- `choose_repository()` opens a native directory chooser, validates the chosen
  directory through `Repo::open`, stores the canonical repository root in Rust
  state, and returns `RepositoryOverview`.
- `select_reference(reference_id)` returns the selected public ref's reachable
  snapshot history, or an explicit opaque private-branch result.
- `snapshot_details(snapshot_id)` returns metadata-only tree entries and changed
  file summaries for a snapshot already reachable from the selected repository.
- `read_file(snapshot_id, path)` returns public text/binary content or an
  explicit locked/unavailable result.
- `compare_first_parent(snapshot_id, path)` lazily returns one public file change
  against the first parent; a root snapshot compares against an empty tree.

Repository paths never enter ordinary IPC calls. Snapshot ids and file paths are
validated against native reachable objects before use. There is no arbitrary
filesystem, shell, URL, or process command.

The DTOs use tagged unions for every confidentiality-sensitive state:

```text
ReferenceAccess = public | private_opaque
TreeState       = public_available | protected_locked | unavailable
ContentState    = text | binary | protected_locked | unavailable
SignatureState  = trusted | untrusted | invalid | unsigned
```

Ciphertext bytes have no field in the public DTO schema. Transcript bodies and
private keys likewise have no DTO representation.

## Repository read model

The adapter reads refs with `scl_repo::refs`, snapshots and objects through the
repository's native `Store`, tree entries through the canonical tree walker, and
signature/transcript metadata through `Repo` APIs. It walks all snapshot parents
for the DAG, not only the first-parent `sc log` view.

The renderer receives presentation-ready, immutable records:

- local and remote-tracking refs, current-ref marker, tip id, and access state;
- DAG nodes with all parent ids, author, timestamp, message, merge marker,
  signature status, transcript count, and ref labels;
- a hierarchical public tree containing path, mode, and a metadata-only access
  state (public-available, locked, or unavailable);
- metadata-only first-parent changes classified as added, modified, deleted, or
  protected, with content fetched only for the selected path;
- file content classified as UTF-8 text, binary, locked, or unavailable.

The model is intentionally small and replaceable. `@pierre/trees` and
`@pierre/diffs` are renderer-only dependencies; their props are built from the
app DTOs inside presentation components and never become Rust types.

The integration spike succeeded against the Tauri/Vite production pipeline and
the jsdom component harness. Both packages render from the local DTOs with
workers disabled. Their current distributions target modern WebViews, so the
bundle target is ES2020; this matches maintained Tauri v2 system WebViews and is
pinned by the production build rather than leaking a compatibility constraint
into the Rust model.

## Private and protected content

Phase 35 is keyless and never decrypts.

- A private ref is identified by its native `BranchManifest`. Its name and the
  accepted manifest metadata may be shown, but its history, paths, messages,
  authors, timestamps, and DAG shape remain opaque.
- A protected tree entry may expose its public path and protection marker, as
  the native public snapshot already does, but its blob is never loaded into a
  renderer content field. File and diff views render a locked explanation.
- Missing promisor objects and corrupt objects are distinct from locked content:
  they render unavailable or corrupt-repository states rather than pretending
  the user lacks authorization.

## Tauri/WebView trust boundary

The WebView is an untrusted presentation process relative to the Rust core.
The frontend is fully bundled, the production CSP denies remote script/content
execution (a separate development CSP permits only the local Vite server), and
the Tauri capability grants only the core window/event functionality needed by
the app. Directory selection is initiated by a Rust command, so no general
dialog or filesystem capability is exposed to frontend JavaScript.

Repository Markdown and HTML are displayed as plain text. File text is rendered
as text, never injected HTML. Errors are sanitized for display and no repository
bytes, identities, environment variables, or IPC payloads are logged.
Repository reads run on Tauri's blocking pool so native object traversal does
not stall IPC dispatch or WebView event handling.

## Test seams

Rust tests exercise the public read-model adapter against temporary native
repositories: valid/open, multi-parent history, metadata/provenance, public
files/diffs, protected locking, private opacity, invalid selection, and corrupt
objects. Frontend tests exercise the user-visible loading, empty, opaque,
locked, corrupt/error, selection, and keyboard-navigation states through the
typed API boundary.

## Scope boundary

There is no commit, amend, merge, rebase, switch, identity import, decryption,
private-branch membership operation, terminal, hosting integration, or updater.
Those require separate mutation and authorization designs.
