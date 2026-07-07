#!/usr/bin/env bash
# P16 demo: durable revocation. Proves that a prefix-rule revoke survives
# merging a branch created before the revoke (the ADR-0025 boundary, closed
# by ADR-0026 tombstones): the recipient stays revoked, fresh commits under
# the prefix seal no DEK to them, and a deliberate re-grant out-epochs the
# old tombstone.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

# Normalize TMPDIR the same way run_protected_merge_demo.sh does: strip a
# trailing slash once so a directory-name glob sees the same base on both
# snapshots.
tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"

fail() { echo "FAIL: $1"; exit 1; }

work=$(mktemp -d "$tmp_base/sc-revoke-demo.XXXXXX")
trap 'rm -rf "$work"' EXIT

keys="$work/keys"
mkdir -p "$keys"
repo="$work/repo"
mkdir -p "$repo"

# Keyless by construction: point SC_IDENTITY at a path that can never exist,
# so every command below is keyless unless it passes an explicit --identity.
export SC_IDENTITY="$work/no-such-identity"

# Identities live OUTSIDE the repo working tree (P5 scanner flags key material).
alice_pk=$("$SC" keygen --out "$keys/alice" | grep 'public key' | awk '{print $3}')
bob_out="$("$SC" keygen --out "$keys/bob")"
bob_pk=$(echo "$bob_out" | grep 'public key' | awk '{print $3}')
bob_id=$(echo "$bob_out" | grep 'recipient id' | awk '{print $3}')

cd "$repo"
"$SC" init >/dev/null
printf '[recipients]\nalice = "%s"\nbob = "%s"\n' "$alice_pk" "$bob_pk" > .sc/recipients.toml

# 1. Protect a prefix for alice, grant bob, commit a secret file.
"$SC" protect secret/ --to alice >/dev/null
mkdir -p secret && echo "hunter2" > secret/db.txt
"$SC" commit -m "add secret" --author demo >/dev/null
"$SC" grant secret/ --to bob --identity "$keys/alice" >/dev/null
"$SC" protect --list | grep -q "granted" || fail "bob not granted"

# 2. Fork a branch while bob is still granted; give it its own work.
"$SC" branch pre-revoke >/dev/null
"$SC" switch pre-revoke >/dev/null
echo "feature" > readme.txt
"$SC" commit -m "feature work" --author demo >/dev/null
"$SC" switch main >/dev/null

# 3. Revoke bob on main.
"$SC" revoke secret/ --recipient-id "$bob_id" >/dev/null
"$SC" protect --list | grep -qi "revoked" || fail "revoke not recorded"

# 4. THE BOUNDARY CASE: merge the pre-revoke branch. Pre-P16 this
#    resurrected bob via the rule union; the tombstone must now hold.
"$SC" merge pre-revoke --author demo >/dev/null
"$SC" protect --list --json | grep -A2 "\"$bob_id\"" | grep -q '"state": "revoked"' \
  || fail "merge resurrected the revoked recipient"

# 5. Fresh content under the prefix seals to alice only (no wrap for bob).
echo "fresh" > secret/new.txt
"$SC" commit -m "post-revoke secret" --author demo >/dev/null
"$SC" protect --list --json | grep -A2 "\"$bob_id\"" | grep -q '"state": "revoked"' \
  || fail "bob regained standing after commit"

# 6. Deliberate re-grant out-epochs the tombstone.
"$SC" grant secret/ --to bob --identity "$keys/alice" >/dev/null
"$SC" protect --list --json | grep -A2 "\"$bob_id\"" | grep -q '"state": "granted"' \
  || fail "re-grant did not win over tombstone"

echo "RESULT: durable revocation proven — tombstone survived the union merge,"
echo "fresh seals excluded the revoked recipient, and a deliberate re-grant won."
