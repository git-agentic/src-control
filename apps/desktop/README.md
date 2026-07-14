# src-control desktop development

Phase 35 is a read-only Tauri v2 browser for native `.sc` repositories. The
Rust backend calls the workspace crates directly; the TypeScript frontend uses
only the five typed commands documented in
[`docs/design/phase-35-desktop-app.md`](../../docs/design/phase-35-desktop-app.md).

## Prerequisites

- Current stable Rust toolchain (`rustup update stable`)
- Node.js with npm
- Tauri v2 platform prerequisites. On macOS, install the Xcode command-line
  tools with `xcode-select --install`. Linux and Windows need the WebView and
  build packages listed by the Tauri v2 prerequisites guide.

## Install and run

From the repository root:

```sh
cd apps/desktop
npm ci
npm run tauri dev
```

Choose this repository's root in the native directory picker. The app validates
the `.sc` repository through `scl_repo::Repo::open`; it does not invoke `sc` or
read a Git export.

## Checks and production build

```sh
cd apps/desktop
npm run typecheck
npm test
npm run build
npm run tauri build -- --bundles app  # macOS application bundle (validated in P35)
# npm run tauri build                 # platform's full configured bundle set

cd ../..
cargo test -p scl-desktop
cargo test --workspace
```

On macOS, the un-signed development bundle is written under
`target/release/bundle/macos/src-control.app`. Other platforms use Tauri's
corresponding bundle directory.

## Security boundary

The desktop slice is keyless. It loads public signer keys for verification, but
never loads identity files or sends private-key bytes over IPC. Protected blobs
return a fieldless `protected_locked` state, private refs stop at public manifest
metadata, and transcript bodies are not part of the read model. The WebView has
no filesystem or shell capability and all scripts are bundled.

`@pierre/trees` and `@pierre/diffs` are presentation adapters only. Their input
is mapped from local DTOs in `src/components/`, keeping both packages
replaceable without changing the native read model.

## Screenshots

The checked-in screenshots use deterministic development-only fixtures so the
public, protected, and private states remain reproducible without embedding
repository content or identities:

- [`screenshots/main-browser.png`](screenshots/main-browser.png)
- [`screenshots/protected-change.png`](screenshots/protected-change.png)
- [`screenshots/private-branch.png`](screenshots/private-branch.png)

With `npm run dev` running, regenerate them from `?demo=main`, `?demo=locked`,
and `?demo=private` at `http://127.0.0.1:1420/`. Demo fixtures are gated by
`import.meta.env.DEV` and are removed from the production entry path.
