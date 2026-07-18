#!/usr/bin/env python3
"""Annotate the Rust SBOM's glib component with its in-tree patch provenance.

`Cargo.lock` records plain `glib 0.18.5`, but the build actually uses the
vendored fork `vendor/glib-0.18.5-patched/` carrying a soundness backport for
RUSTSEC-2024-0429 (see that directory's PROVENANCE.md). A version-keyed SBOM
consumer would otherwise misread the component as unpatched upstream — the
exact false positive OSTIF audit G-033 documents. This script records the
patch as CycloneDX pedigree on the component.

Usage: annotate_sbom_glib.py <sbom.cdx.json>   (edits the file in place)

Fails loudly if no glib component is found: if the vendored patch has been
removed (GTK4 migration removal gate), delete this step and this script in
the same PR.
"""

import json
import sys

PROVENANCE_URL = (
    "https://github.com/git-agentic/src-control/blob/main/"
    "vendor/glib-0.18.5-patched/PROVENANCE.md"
)

def main(path: str) -> None:
    with open(path) as f:
        sbom = json.load(f)

    glib = [
        c
        for c in sbom.get("components", [])
        if c.get("name") == "glib" and c.get("purl", "").startswith("pkg:cargo/glib@")
    ]
    if not glib:
        sys.exit(
            "no cargo glib component found in SBOM — if the vendored patch "
            "was removed, delete this annotation step and script"
        )

    for c in glib:
        c["pedigree"] = {
            "patches": [
                {
                    "type": "backport",
                    "diff": {"url": PROVENANCE_URL},
                    "resolves": [
                        {
                            "type": "security",
                            "id": "RUSTSEC-2024-0429",
                            "source": {"name": "RustSec"},
                        }
                    ],
                }
            ]
        }
        c.setdefault("properties", []).append(
            {
                "name": "src-control:vendored-patched-copy",
                "value": (
                    "built from vendor/glib-0.18.5-patched (in-tree fork, "
                    "[patch.crates-io]); NOT the unpatched upstream 0.18.5"
                ),
            }
        )

    with open(path, "w") as f:
        json.dump(sbom, f, indent=2)
    print(f"annotated {len(glib)} glib component(s) in {path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
