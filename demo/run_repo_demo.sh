#!/usr/bin/env bash
# End-to-end proof: a persistent repo survives across separate `sc` invocations,
# including a committed secret that decrypts in a later process.
set -euo pipefail

# Build once and resolve the binary to an absolute path BEFORE we cd away.
cargo build --bin sc >/dev/null 2>&1
SC="$(pwd)/target/debug/sc"

WORK="$(mktemp -d)"
# Identity file lives outside WORK so the secret scanner never sees it during commit.
KEYS="$(mktemp -d)"
MIRROR_BASE="$(mktemp -d)"
trap 'rm -rf "$WORK" "$KEYS" "$MIRROR_BASE"' EXIT

# Generate an identity (private key + public key for recipients.toml).
PUB="$("$SC" keygen --out "$KEYS/id" | grep 'public key' | awk '{print $3}')"

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

SC_IDENTITY="$KEYS/id" "$SC" secret add DB_URL --to me --value "postgres://app"
# A *new* `sc` process reads the secret back, proving cross-invocation persistence:
OUT="$(SC_IDENTITY="$KEYS/id" "$SC" run -- sh -c 'printf %s "$DB_URL"')"
[ "$OUT" = "postgres://app" ] || { echo "FAIL: secret did not survive/inject ($OUT)"; exit 1; }

# Regression guard: `sc run` must release the repo lock on exit. If it leaks the
# lock (e.g. process::exit skipping Drop), the next command fails with `Locked`.
"$SC" status >/dev/null || { echo "FAIL: repo locked after run (lock leak)"; exit 1; }

echo
echo "== GC compaction =="
# Committing several times produces many small loose objects in .sc/objects/.
# sc gc consolidates all reachable objects into a single compressed packfile and
# removes the redundant loose files, reclaiming space.  (Pruning additionally
# reclaims objects that are truly unreachable — from amended or abandoned work —
# but this demo shows the compaction path.)
# Use dd+tr (no secrets) instead of /dev/urandom to avoid triggering the secret scanner.
dd if=/dev/zero bs=1048576 count=1 2>/dev/null | tr '\0' 'A' > "$WORK/big.bin"
"$SC" commit -m "add big.bin" --author me
dd if=/dev/zero bs=1048576 count=1 2>/dev/null | tr '\0' 'B' > "$WORK/big.bin"
"$SC" commit -m "replace big.bin" --author me

before=$(du -sk "$WORK/.sc/objects" | cut -f1)
echo "objects size before gc: ${before} KiB"
# Zero grace period so any unreachable objects are immediately eligible for pruning.
"$SC" gc --prune-expire 0s
after=$(du -sk "$WORK/.sc/objects" | cut -f1)
echo "objects size after gc:  ${after} KiB"
if [ "$after" -lt "$before" ]; then
  echo "OK: gc compacted loose objects and reclaimed space"
else
  echo "WARN: gc did not shrink objects (small repo / fs rounding)"
fi

echo
echo "== Git export =="
# This repo carries a committed secret (DB_URL).  Export is fail-closed by
# default; --include-encrypted allows it: protected files export as ciphertext
# and registry secrets are silently dropped (no plaintext leaks into Git).
MIRROR="$MIRROR_BASE/mirror.git"
"$SC" export --to "$MIRROR" --include-encrypted
echo "git sees the exported history:"
git --git-dir "$MIRROR" log --oneline | sed 's/^/  /'

echo "RESULT: persistent repo survived across invocations; secret decrypted in a new process ✔"
