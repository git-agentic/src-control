#!/usr/bin/env bash
# P10 demo: git as a bidirectional remote. Proves sc push -> git log reads it,
# and a second sc repo fetch+merge gets the content back.
set -euo pipefail

# Build once and resolve the binary to an absolute path BEFORE we cd away.
cargo build --bin sc >/dev/null 2>&1
SC="$(pwd)/target/debug/sc"

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

WORK="$ROOT/work"; BARE="$ROOT/target.git"; CLONE="$ROOT/clone"
mkdir -p "$WORK" "$CLONE"

echo "== author sc history =="
( cd "$WORK" && $SC init && echo v1 > f.txt && $SC commit -m c1 && echo v2 > f.txt && $SC commit -m c2 )

echo "== push to a bare git repo =="
git init -q --bare "$BARE"
( cd "$WORK" && $SC remote add hub "$BARE" --git && $SC push hub )

echo "== git log reads the pushed history =="
git --git-dir="$BARE" log --oneline main

echo "== a second sc repo fetches + merges it back =="
( cd "$CLONE" && $SC init && $SC remote add hub "$BARE" --git && $SC fetch hub && $SC merge hub/main && cat f.txt )

echo "OK: git-as-a-remote round-trip verified"
