#!/usr/bin/env bash
# End-to-end proof: a persistent repo survives across separate `sc` invocations,
# including a committed secret that decrypts in a later process.
set -euo pipefail

# Build once and resolve the binary to an absolute path BEFORE we cd away.
cargo build --bin sc >/dev/null 2>&1
SC="$(pwd)/target/debug/sc"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# Generate an identity (private key + public key for recipients.toml).
PUB="$("$SC" keygen --out "$WORK/id" | grep 'public key' | awk '{print $3}')"

cd "$WORK"
"$SC" init                                   # creates ./.sc (must not pre-exist)
printf '[recipients]\nme = "%s"\n' "$PUB" > .sc/recipients.toml

echo "v1" > app.txt
"$SC" commit -m "first commit" --author me
"$SC" branch feature
"$SC" switch feature
echo "feature" > feature.txt
"$SC" commit -m "feature work" --author me
"$SC" switch main
[ ! -f feature.txt ] || { echo "FAIL: feature.txt should be gone on main"; exit 1; }

SC_IDENTITY="$WORK/id" "$SC" secret add DB_URL --to me --value "postgres://app"
# A *new* `sc` process reads the secret back, proving cross-invocation persistence:
OUT="$(SC_IDENTITY="$WORK/id" "$SC" run -- sh -c 'printf %s "$DB_URL"')"
[ "$OUT" = "postgres://app" ] || { echo "FAIL: secret did not survive/inject ($OUT)"; exit 1; }

# Regression guard: `sc run` must release the repo lock on exit. If it leaks the
# lock (e.g. process::exit skipping Drop), the next command fails with `Locked`.
"$SC" status >/dev/null || { echo "FAIL: repo locked after run (lock leak)"; exit 1; }

echo "RESULT: persistent repo survived across invocations; secret decrypted in a new process ✔"
