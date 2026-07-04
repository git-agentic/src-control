#!/usr/bin/env bash
# P11 demo: secret rotation + break-glass escrow. Proves escrow auto-inclusion,
# that rotation changes the injected value, and that escrow recovers the
# rotated value. Ends by stating the rotation-is-not-erasure caveat.
set -euo pipefail

# Build once and resolve the binary to an absolute path BEFORE we cd away.
cargo build --bin sc >/dev/null 2>&1
SC="$(pwd)/target/debug/sc"

ROOT="$(mktemp -d)"
# Identity files live outside ROOT so the secret scanner never sees them during commit.
KEYS="$(mktemp -d)"
trap 'rm -rf "$ROOT" "$KEYS"' EXIT

REPO="$ROOT/repo"
mkdir -p "$REPO"

alice_pk=$("$SC" keygen --out "$KEYS/alice" | grep 'public key' | awk '{print $3}')
escrow_pk=$("$SC" keygen --out "$KEYS/escrow" | grep 'public key' | awk '{print $3}')

cd "$REPO"
"$SC" init >/dev/null
printf '[recipients]\nalice = "%s"\n' "$alice_pk" > .sc/recipients.toml

echo "== set escrow key =="
"$SC" escrow set "$escrow_pk"

echo "== add secret to alice only (escrow auto-included) =="
"$SC" secret add DB_URL --to alice --value 'v0'
"$SC" secret list

echo "== rotate to a new value =="
"$SC" secret rotate DB_URL --value 'v1'

echo "escrow recovers rotated value:"
OUT="$(SC_IDENTITY="$KEYS/escrow" "$SC" run -- sh -c 'printf %s "$DB_URL"')"
[ "$OUT" = "v1" ] || { echo "FAIL: escrow did not recover rotated value ($OUT)"; exit 1; }
echo "  DB_URL=$OUT"

echo
echo "OK: rotation + escrow verified"
echo "caveat: rotation cuts off future registry reads; the old ciphertext remains in history."
