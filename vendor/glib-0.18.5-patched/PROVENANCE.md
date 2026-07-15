# Patched glib 0.18.5

This directory is the published `glib` 0.18.5 crate source, copied from the
Cargo registry package whose lockfile checksum is
`233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5`.

It carries the upstream fix for RUSTSEC-2024-0429 from
<https://github.com/gtk-rs/gtk-rs-core/pull/1343>:

- make the `VariantStrIter::impl_get` out pointer mutable; and
- pass `&mut p` to `g_variant_get_child` instead of writing through `&p`.

Apart from this file, those two lines in `src/variant_iter.rs`, and a crate-level
`allow(warnings)` in `src/lib.rs`, the directory matches the published crate.
The lint cap reproduces Cargo's treatment of registry dependencies now that this
copy is a path dependency; it does not change runtime behavior. `cargo audit`
matches by package name and version, so the workflow must continue ignoring
RUSTSEC-2024-0429 even though the runtime code is patched.

Remove this directory, the workspace exclusion, the `[patch.crates-io]` entry,
and the audit exception when Tauri's Linux stack uses `glib` 0.20 or newer.
