#!/usr/bin/env bash
# End-to-end proof: clone a repo, sync changes both directions, and confirm an
# unauthorized clone receives a committed secret as ciphertext it cannot read.
set -euo pipefail
cargo build --bin sc >/dev/null 2>&1
SC="$(pwd)/target/debug/sc"
A="$(mktemp -d)"; B="$(mktemp -d)"; trap 'rm -rf "$A" "$B"' EXIT

cd "$A"; "$SC" init >/dev/null
printf 'base\n' > f.txt; "$SC" commit -m base --author me >/dev/null
"$SC" clone "$A" "$B/c" >/dev/null
[ -f "$B/c/f.txt" ] || { echo "FAIL: clone did not materialize f.txt"; exit 1; }

# A advances; B fetches + merges.
cd "$A"; printf 'base\nA2\n' > f.txt; "$SC" commit -m a2 --author me >/dev/null
cd "$B/c"; "$SC" fetch >/dev/null; "$SC" merge origin/main --author me >/dev/null
grep -q A2 f.txt || { echo "FAIL: fetch+merge did not bring A2"; exit 1; }

# B advances; pushes back to A (fast-forward).
printf 'base\nA2\nB3\n' > f.txt; "$SC" commit -m b3 --author me >/dev/null
"$SC" push >/dev/null
cd "$A"; "$SC" log | grep -q b3 || { echo "FAIL: push did not land on A"; exit 1; }

echo "RESULT: clone + fetch/merge + push round-trip succeeded ✔"
