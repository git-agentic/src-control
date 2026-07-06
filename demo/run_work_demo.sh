#!/usr/bin/env bash
# P13 proof: `sc work` forks N agent workspaces, harvests them to branches,
# merge integrates them, and the session leaves zero residue outside .sc/.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

# Normalize TMPDIR: on macOS it's typically /var/folders/.../T/ with a
# trailing slash. mktemp tolerates that, but a bare directory-name glob
# (`find "$TMPDIR" -name 'sc-work-*'`) must see the same base both times, so
# strip the trailing slash once and reuse it everywhere.
tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"

fail() { echo "FAIL: $1"; exit 1; }

work=$(mktemp -d "$tmp_base/sc-work-demo.XXXXXX")
trap 'rm -rf "$work"' EXIT
repo="$work/repo"
mkdir -p "$repo"
cd "$repo"

echo "=== setup: persistent repo with a base commit ==="
"$SC" init
printf 'alpha\n' > alpha.txt
printf 'beta\n'  > beta.txt
"$SC" commit -m "base" --author demo

echo
echo "=== snapshot the filesystem outside .sc/ (before) ==="
before=$(mktemp "$work/before.XXXXXX")
find "$tmp_base" -maxdepth 1 -name 'sc-work-*' 2>/dev/null | sort > "$before" || true

echo
echo "=== sc work: 3 agents, each edits a distinct file ==="
"$SC" work --agents 3 --author demo -- \
  sh -c 'echo "edited by $SC_WORKSPACE" > "file-$SC_WORKSPACE.txt"'

echo
echo "=== three branches exist and merge cleanly ==="
for i in 1 2 3; do
  "$SC" merge "work-$i" --author demo
done
"$SC" log | head -12
for i in 1 2 3; do
  test -f "file-work-$i.txt" || { echo "FAIL: missing file-work-$i.txt"; exit 1; }
done
echo "all three agents' edits merged ✔"

echo
echo "=== secrets leg: agents see the decrypted secret in their env ==="
# Recipient bootstrap: same pattern as demo/run_lifecycle_demo.sh.
key="$work/identity"
pk=$("$SC" keygen --out "$key" | grep 'public key' | awk '{print $3}')
printf '[recipients]\ndemo = "%s"\n' "$pk" > .sc/recipients.toml
"$SC" secret add DEMO_TOKEN --to demo --value 'tok-123'
"$SC" work --agents 1 --name sec --with-secrets --identity "$key" --author demo -- \
  sh -c 'printf "len=%s" "${#DEMO_TOKEN}" > secret-proof.txt'
"$SC" merge sec-1 --author demo
grep -q 'len=7' secret-proof.txt || fail "secret did not reach agent env"
echo "secret reached the agent env ✔"

echo
echo "=== zero-residue proof: no session dirs left in TMPDIR ==="
after=$(mktemp "$work/after.XXXXXX")
find "$tmp_base" -maxdepth 1 -name 'sc-work-*' 2>/dev/null | sort > "$after" || true
diff "$before" "$after" || fail "residual session directories left in $tmp_base"
echo "no residual session directories ✔"

echo
echo "RESULT: parallel agents → branches → merge, zero residue ✔"
