#!/usr/bin/env bash
# Headline proof for P26 (sc-native transport over HTTP): clone/push/fetch
# run against a real `sc+http://` remote — no shim required, unlike the
# ssh:// demo, because HTTP is real loopback TCP end to end: `sc serve
# --http 127.0.0.1:<port> <repo>` binds a genuine `TcpListener` and
# `sc clone sc+http://127.0.0.1:<port>/repo <dst>` dials it directly. A
# large (~1 MiB) blob is committed and signed so the P25 streaming pack path
# and the P22 signature-riding-the-wire path both get exercised over the
# real socket, with `SC_PACK_CHUNK` forced tiny so the transfer crosses many
# chunk frames instead of one.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

fail() { echo "FAIL: $1"; exit 1; }

W="$(mktemp -d)"
A="$W/A"
KEY="$W/alice.key"
SERVER_PID=""

cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$W"
}
trap cleanup EXIT

# --- Pick a port; probe with `nc -z` first and fall back if it's taken. ---
pick_port() {
  local candidate
  for candidate in 8731 8732 8733 8899 18731; do
    if ! nc -z 127.0.0.1 "$candidate" 2>/dev/null; then
      echo "$candidate"
      return 0
    fi
  done
  fail "no free port found among the candidates"
}
PORT="$(pick_port)"

wait_for_port() {
  local tries=0
  while ! nc -z 127.0.0.1 "$PORT" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -lt 100 ] || fail "server on port $PORT never became ready"
    sleep 0.05
  done
}

# --- Force many chunk frames: SC_PACK_CHUNK overrides wire::pack_chunk_size()
#     (a ~1 MiB blob over a 4 KiB chunk crosses roughly 250+ frames). ---
: "${SC_PACK_CHUNK:=4096}"
export SC_PACK_CHUNK

echo "=== setup: keygen v2 for alice (trusted signer) ==="
alice_out=$("$SC" keygen --out "$KEY")
alice_sig=$(echo "$alice_out" | awk '/signing key:/{print $3}')
[ -n "$alice_sig" ] || fail "alice's signing key missing from keygen output"
echo "alice signing key: $alice_sig"

echo
echo "=== 1: init A, commit a ~1 MiB blob, sign it ==="
mkdir -p "$A"; cd "$A"
"$SC" init >/dev/null
{
  printf '[signing]\n'
  printf 'alice = "%s"\n' "$alice_sig"
  printf '\n[signers]\n'
  printf 'trusted = ["alice"]\n'
} > .sc/recipients.toml
head -c 1048576 /dev/urandom | od -An -tx1 | tr -d ' \n' > big.bin
blob_before=$(shasum -a 256 big.bin | awk '{print $1}')
printf 'small\n' > small.txt
"$SC" commit -m "add big blob" --author alice --sign --identity "$KEY" >/dev/null
log_before=$("$SC" log)
echo "A: ~1 MiB blob + small file committed and signed ✔"

echo
echo "=== 2: sc serve --http 127.0.0.1:$PORT (background), wait for readiness ==="
cd "$W"
"$SC" serve --http "127.0.0.1:$PORT" "$A" &
SERVER_PID=$!
wait_for_port
echo "server: listening on 127.0.0.1:$PORT (pid $SERVER_PID) ✔"

URL="sc+http://127.0.0.1:$PORT/repo"

run_one_clone() {
  local dst="$1" label="$2"
  cd "$W"
  "$SC" clone "$URL" "$dst" >/dev/null

  # `[signers] trusted` is local trust policy, not repo content — clone
  # never copies .sc/recipients.toml. Mirror A's trust config so `sc log`'s
  # signed marker and `sc verify --require` compare like for like.
  cp "$A/.sc/recipients.toml" "$dst/.sc/recipients.toml"

  # --- object set byte-for-byte. ---
  diff <(cd "$A" && find .sc/objects -type f | sort) \
       <(cd "$dst" && find .sc/objects -type f | sort) \
    || fail "$label: object set differs from origin"

  # --- working tree byte-for-byte. ---
  [ "$(shasum -a 256 "$dst/big.bin" | awk '{print $1}')" = "$blob_before" ] \
    || fail "$label: big.bin is not byte-identical to the origin"
  [ "$(cat "$dst/small.txt")" = "small" ] || fail "$label: small.txt did not survive the wire"

  # --- history identical. ---
  cd "$dst"
  [ "$("$SC" log)" = "$log_before" ] || fail "$label: sc log differs from origin"

  # --- signature rode the stream. ---
  "$SC" verify --require | tail -1 | grep -q '0 untrusted, 0 invalid, 0 unsigned' \
    || fail "$label: sc verify --require is not clean in the clone"
  echo "$label: object set + working tree + log byte-for-byte, sc verify --require clean ✔"

  # --- zero temp residue on the clone end after a successful transfer. ---
  [ -d "$dst/.sc/tmp" ] && [ -n "$(ls -A "$dst/.sc/tmp" 2>/dev/null)" ] \
    && fail "$label: clone's .sc/tmp is not empty after the transfer"
  echo "$label: zero .sc/tmp residue on the clone end ✔"
}

echo
echo "=== 3: sc clone sc+http://127.0.0.1:$PORT/repo (SC_PACK_CHUNK=$SC_PACK_CHUNK) ==="
run_one_clone "$W/B1" "B1 (first clone)"

echo
echo "=== 4: run again into a fresh destination — repeatable, not a one-shot fluke ==="
run_one_clone "$W/B2" "B2 (second clone)"

echo
echo "=== 5: a second clone commits and pushes back over sc+http:// ==="
cd "$W/B1"
printf 'pushed from B1 over http\n' > from_b1.txt
"$SC" commit -m "from-B1-http" --author b1 >/dev/null
"$SC" push origin >/dev/null
cd "$A"
"$SC" log | grep -q "from-B1-http" || fail "A's history lacks the pushed commit"
echo "B1 -> A: push over sc+http:// landed ✔"

echo
echo "=== 6: B2 fetches and sees the pushed commit ==="
cd "$W/B2"
"$SC" fetch origin >/dev/null
"$SC" merge origin/main >/dev/null
"$SC" log | grep -q "from-B1-http" || fail "B2 did not see the pushed commit after fetch+merge"
echo "B2: fetch + merge sees B1's push ✔"

echo
echo "=== 7: zero .sc/tmp residue on the origin end too ==="
[ -d "$A/.sc/tmp" ] && [ -n "$(ls -A "$A/.sc/tmp" 2>/dev/null)" ] \
  && fail "origin's .sc/tmp is not empty after serving multiple transfers"
echo "A: zero .sc/tmp residue after serving clones/push/fetch ✔"

echo
echo "=== 8: stop the server ==="
kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
! nc -z 127.0.0.1 "$PORT" 2>/dev/null || fail "server still accepting connections after kill"
echo "server: stopped, port released ✔"

echo
echo "RESULT: sc-native transport over sc+http:// — real loopback TCP, no ssh"
echo "account or shim required — clone, push, fetch, a streamed ~1 MiB blob"
echo "across many SC_PACK_CHUNK=$SC_PACK_CHUNK frames, a signature riding the same"
echo "wire verifying clean in every clone, and zero .sc/tmp residue on either end."
