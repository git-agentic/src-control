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

## Pinned deltas (machine-checked)

CI (`.github/workflows/vendor-provenance.yml`, running
`.github/scripts/verify_glib_provenance.py`) downloads the published crate,
verifies it against `crate-sha256`, and diffs it against this directory. It
fails on any difference not listed below, and on any listed file whose content
no longer matches its pinned hash — so changing a delta requires updating its
hash here in the same change. This file itself is the only addition.

```provenance
crate-sha256: 233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5
# RUSTSEC-2024-0429 backport (gtk-rs-core#1343)
delta: src/variant_iter.rs sha256=a0f5ee8acb8faa089bcdfbc9a57372609fce7654026ccef7d9a224d05a654ccc
# crate-level allow(warnings), reproducing Cargo's --cap-lints for registry deps
delta: src/lib.rs sha256=f118b6507cf8c7176a70963ec6ad890f5020559cf4e5a87131eddae61e4fcb3a
```

Remove this directory, the workspace exclusion, the `[patch.crates-io]` entry,
and the audit exception when Tauri's Linux stack uses `glib` 0.20 or newer.
