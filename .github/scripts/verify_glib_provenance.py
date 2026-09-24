#!/usr/bin/env python3
"""Verify the vendored glib tree against the published crate (issue #71).

`vendor/glib-0.18.5-patched/` compiles into every Linux desktop build, and its
PROVENANCE.md claims the directory is the published `glib` 0.18.5 source apart
from a small set of documented deltas. This script enforces that claim:

1. Parse the pinned crate checksum and delta list from PROVENANCE.md (the
   fenced "Pinned deltas" block — the one place a reviewer reads them).
2. Download the `.crate` from crates.io (or read `--crate <path>`) and verify
   it against the pinned checksum.
3. Diff the extracted source against the vendored tree. Fail unless every
   difference is a documented delta whose file matches its pinned SHA-256,
   and every documented delta is an actual difference.

Editing a delta file therefore fails CI unless PROVENANCE.md is updated in the
same change; any other edit, addition, or removal fails outright.

Usage: verify_glib_provenance.py [--crate <glib-0.18.5.crate>]

Removal gate: delete this script and its workflow together with the vendored
directory when Tauri's Linux stack uses glib >= 0.20.
"""

import argparse
import hashlib
import io
import os
import re
import sys
import tarfile
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VENDOR_DIR = os.path.join(REPO_ROOT, "vendor", "glib-0.18.5-patched")
MANIFEST = "PROVENANCE.md"
CRATE_NAME, CRATE_VERSION = "glib", "0.18.5"
CRATE_URL = (
    f"https://static.crates.io/crates/{CRATE_NAME}/"
    f"{CRATE_NAME}-{CRATE_VERSION}.crate"
)

BLOCK_RE = re.compile(r"```provenance\n(.*?)```", re.S)
CRATE_LINE_RE = re.compile(r"^crate-sha256: ([0-9a-f]{64})$")
DELTA_LINE_RE = re.compile(r"^delta: (\S+) sha256=([0-9a-f]{64})$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_manifest(text: str) -> tuple[str, dict[str, str]]:
    """Return (pinned crate checksum, {relative path: pinned sha256})."""
    blocks = BLOCK_RE.findall(text)
    if len(blocks) != 1:
        sys.exit(f"{MANIFEST}: expected exactly one ```provenance block, found {len(blocks)}")
    crate_sum, deltas = None, {}
    for line in blocks[0].splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if m := CRATE_LINE_RE.match(line):
            if crate_sum is not None:
                sys.exit(f"{MANIFEST}: duplicate crate-sha256 line")
            crate_sum = m.group(1)
        elif m := DELTA_LINE_RE.match(line):
            path, digest = m.groups()
            if path == MANIFEST or path in deltas:
                sys.exit(f"{MANIFEST}: invalid or duplicate delta {path!r}")
            deltas[path] = digest
        else:
            sys.exit(f"{MANIFEST}: unrecognised provenance line {line!r}")
    if crate_sum is None:
        sys.exit(f"{MANIFEST}: missing crate-sha256 line")
    return crate_sum, deltas


def upstream_files(crate_bytes: bytes) -> dict[str, bytes]:
    """Map relative path -> content for every regular file in the .crate."""
    prefix = f"{CRATE_NAME}-{CRATE_VERSION}/"
    files = {}
    with tarfile.open(fileobj=io.BytesIO(crate_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.isdir():
                continue
            if not member.isfile() or not member.name.startswith(prefix):
                sys.exit(f"unexpected entry in published crate: {member.name!r}")
            files[member.name[len(prefix):]] = tar.extractfile(member).read()
    return files


def vendored_files() -> dict[str, bytes]:
    """Map relative path -> content for every file under the vendored tree."""
    files = {}
    for root, dirs, names in os.walk(VENDOR_DIR, followlinks=False):
        for name in dirs + names:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, VENDOR_DIR).replace(os.sep, "/")
            if os.path.islink(full):
                sys.exit(f"vendored tree contains a symlink: {rel}")
            if name in names:
                with open(full, "rb") as f:
                    files[rel] = f.read()
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--crate", help="read the .crate from this path instead of crates.io")
    args = parser.parse_args()

    vendored = vendored_files()
    if MANIFEST not in vendored:
        sys.exit(f"{MANIFEST} missing from {VENDOR_DIR}")
    crate_sum, deltas = parse_manifest(vendored.pop(MANIFEST).decode())

    if args.crate:
        with open(args.crate, "rb") as f:
            crate_bytes = f.read()
    else:
        with urllib.request.urlopen(CRATE_URL, timeout=60) as resp:
            crate_bytes = resp.read()
    actual_sum = sha256(crate_bytes)
    if actual_sum != crate_sum:
        sys.exit(f"crate checksum mismatch: pinned {crate_sum}, downloaded {actual_sum}")
    upstream = upstream_files(crate_bytes)

    errors = []
    for path in sorted(set(upstream) | set(vendored)):
        if path not in vendored:
            errors.append(f"removed from vendored tree: {path}")
        elif path not in upstream:
            errors.append(f"added to vendored tree (undocumented): {path}")
        elif upstream[path] == vendored[path]:
            if path in deltas:
                errors.append(f"documented delta is identical to upstream: {path}")
        elif path not in deltas:
            errors.append(f"undocumented change: {path}")
        elif sha256(vendored[path]) != deltas[path]:
            errors.append(
                f"delta {path} changed without updating {MANIFEST} "
                f"(now sha256={sha256(vendored[path])})"
            )
    for path in sorted(set(deltas) - set(upstream)):
        errors.append(f"documented delta is not a published file: {path}")

    if errors:
        print("vendored glib provenance check FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)
    print(
        f"vendored glib {CRATE_VERSION} matches the published crate "
        f"({crate_sum[:12]}…) apart from {len(deltas)} documented delta(s) "
        f"and {MANIFEST}"
    )


if __name__ == "__main__":
    main()
