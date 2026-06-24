#!/usr/bin/env bash
#
# Independent zero-residue proof for the Phase 1 in-memory worktree engine.
#
# This script does NOT trust the binary's own self-check. It snapshots the
# filesystem (the temp dir where worktrees materialize, and the project tree)
# BEFORE and AFTER running the demo, then diffs them. A pass means the run left
# no new files anywhere we can see.

set -euo pipefail

cd "$(dirname "$0")/.."
PROJECT_DIR="$(pwd)"
TMP="${TMPDIR:-/tmp}"
TMP="${TMP%/}"

echo "project dir: $PROJECT_DIR"
echo "temp dir:    $TMP"
echo

# --- BEFORE snapshot --------------------------------------------------------
# Any pre-existing scl-* entries in the temp dir (should be none).
before_tmp="$(find "$TMP" -maxdepth 1 -name 'scl-*' 2>/dev/null | sort || true)"
# The set of files tracked in the project (excluding the build cache).
before_proj="$(find "$PROJECT_DIR" -type f -not -path '*/target/*' 2>/dev/null | sort)"

# --- RUN --------------------------------------------------------------------
echo ">>> running: sc demo --agents 8 --budget-mb 4 --spill"
echo "---------------------------------------------------------------"
cargo run --quiet --bin sc -- demo --agents 8 --budget-mb 4 --spill
echo "---------------------------------------------------------------"
echo

# --- AFTER snapshot ---------------------------------------------------------
after_tmp="$(find "$TMP" -maxdepth 1 -name 'scl-*' 2>/dev/null | sort || true)"
after_proj="$(find "$PROJECT_DIR" -type f -not -path '*/target/*' 2>/dev/null | sort)"

# --- DIFF -------------------------------------------------------------------
fail=0

if [ "$before_tmp" != "$after_tmp" ]; then
  echo "FAIL: temp dir changed — residual worktree/spill artifacts:"
  diff <(printf '%s\n' "$before_tmp") <(printf '%s\n' "$after_tmp") || true
  fail=1
else
  echo "PASS: no residual scl-* artifacts in temp dir."
fi

if [ "$before_proj" != "$after_proj" ]; then
  echo "FAIL: project tree changed during the run:"
  diff <(printf '%s\n' "$before_proj") <(printf '%s\n' "$after_proj") || true
  fail=1
else
  echo "PASS: project tree unchanged."
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "ZERO-RESIDUE PROOF: PASSED ✔"
else
  echo "ZERO-RESIDUE PROOF: FAILED"
  exit 1
fi
