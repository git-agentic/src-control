#!/usr/bin/env bash
# P37 demo: want-by-id fetch on a lazy partial clone (ADR-0047). Proves that
# `sc cat <ref>:<path>` on a `--lazy` partial clone fetches ONLY the trees and
# the blob on the path it reads (by object id, one batch per tree depth), that
# a sibling file stays unfetched, that a non-lazy clone and `SC_OFFLINE=1`
# keep the loud gap error with zero network, and that the same fetch works
# over a real `sc+http://` loopback server (protocol v5 `GetObjects`).
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

fail() { echo "FAIL: $1"; exit 1; }

W="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$W"
}
trap cleanup EXIT

objects() { find "$1/.sc/objects" -type f | wc -l | tr -d ' '; }

ORIGIN="$W/origin"
mkdir -p "$ORIGIN"
(
  cd "$ORIGIN"
  "$SC" init >/dev/null
  mkdir -p src docs/api
  printf 'fn main() {}\n' > src/a.txt
  head -c 65536 /dev/urandom | od -An -tx1 | tr -d ' \n' > docs/api/guide.bin
  head -c 65536 /dev/urandom | od -An -tx1 | tr -d ' \n' > docs/api/other.bin
  "$SC" commit -m "base" --author demo >/dev/null
)
FULL=$(objects "$ORIGIN")
echo "origin: src/ + docs/api/{guide,other}.bin committed; $FULL object(s) ✔"

echo
echo "=== 1: lazy partial clone (--filter src/ --lazy) fetches only src/ ==="
LAZY="$W/lazy"
"$SC" clone --filter src/ --lazy "$ORIGIN" "$LAZY" >/dev/null
BEFORE=$(objects "$LAZY")
[ "$BEFORE" -lt "$FULL" ] || fail "partial clone must hold fewer objects ($BEFORE) than the origin ($FULL)"
[ -f "$LAZY/.sc/promisor-lazy" ] || fail "--lazy must write .sc/promisor-lazy"
echo "lazy clone: $BEFORE object(s) of $FULL ✔"

echo
echo "=== 2: sc cat fetches exactly the path it reads ==="
(cd "$LAZY" && "$SC" cat main:docs/api/guide.bin) > "$W/guide.out"
cmp "$W/guide.out" "$ORIGIN/docs/api/guide.bin" || fail "cat output must be byte-identical to the origin file"
AFTER=$(objects "$LAZY")
# docs tree + docs/api tree + guide blob = 3 new objects, and not other.bin.
[ "$((AFTER - BEFORE))" -eq 3 ] || fail "expected exactly 3 new objects (2 trees + 1 blob), got $((AFTER - BEFORE))"
[ "$AFTER" -lt "$FULL" ] || fail "the sibling blob must still be unfetched ($AFTER of $FULL)"
echo "cat main:docs/api/guide.bin: byte-identical, +3 objects, sibling other.bin not fetched ✔"

echo
echo "=== 3: a second cat of the same path fetches nothing ==="
(cd "$LAZY" && "$SC" cat main:docs/api/guide.bin) > /dev/null
[ "$(objects "$LAZY")" -eq "$AFTER" ] || fail "re-reading a filled path must not fetch"
echo "re-read: no new objects ✔"

echo
echo "=== 4: SC_OFFLINE=1 keeps the loud gap error, with zero network ==="
BEFORE_OFF=$(objects "$LAZY")
if (cd "$LAZY" && SC_OFFLINE=1 "$SC" cat main:docs/api/other.bin) >/dev/null 2>"$W/off.err"; then
  fail "offline cat of an unfetched path must fail"
fi
grep -q "backfill" "$W/off.err" || fail "offline error must point at sc backfill: $(cat "$W/off.err")"
[ "$(objects "$LAZY")" -eq "$BEFORE_OFF" ] || fail "offline cat must not fetch"
echo "SC_OFFLINE=1: gap error mentions sc backfill, nothing fetched ✔"

echo
echo "=== 5: a non-lazy partial clone keeps the P27 gap error ==="
EAGER="$W/eager"
"$SC" clone --filter src/ "$ORIGIN" "$EAGER" >/dev/null
EAGER_BEFORE=$(objects "$EAGER")
if (cd "$EAGER" && "$SC" cat main:docs/api/guide.bin) >/dev/null 2>"$W/eager.err"; then
  fail "non-lazy partial clone must not fetch on read"
fi
grep -q "backfill" "$W/eager.err" || fail "non-lazy error must point at sc backfill: $(cat "$W/eager.err")"
[ "$(objects "$EAGER")" -eq "$EAGER_BEFORE" ] || fail "non-lazy cat must not fetch"
echo "non-lazy clone: gap error, nothing fetched ✔"

echo
echo "=== 6: sc backfill --lazy opts an existing partial clone in ==="
(cd "$EAGER" && "$SC" backfill --lazy >/dev/null)
(cd "$EAGER" && "$SC" cat main:docs/api/other.bin) > "$W/other.out"
cmp "$W/other.out" "$ORIGIN/docs/api/other.bin" || fail "lazy-after-the-fact cat must be byte-identical"
echo "backfill --lazy then cat: byte-identical ✔"

echo
echo "=== 7: the same fetch over a real sc+http:// loopback server (protocol v5) ==="
pick_port() {
  local candidate
  for candidate in 8741 8742 8743 8899 18741; do
    if ! nc -z 127.0.0.1 "$candidate" 2>/dev/null; then echo "$candidate"; return 0; fi
  done
  fail "no free port found"
}
PORT="$(pick_port)"
"$SC" serve --http "127.0.0.1:$PORT" --read-only "$ORIGIN" >/dev/null 2>&1 &
SERVER_PID=$!
tries=0
while ! nc -z 127.0.0.1 "$PORT" 2>/dev/null; do
  tries=$((tries + 1)); [ "$tries" -lt 100 ] || fail "server never became ready"; sleep 0.05
done
HTTP="$W/http"
"$SC" clone --filter src/ --lazy "sc+http://127.0.0.1:$PORT/repo" "$HTTP" >/dev/null
(cd "$HTTP" && "$SC" cat main:docs/api/guide.bin) > "$W/http.out"
cmp "$W/http.out" "$ORIGIN/docs/api/guide.bin" || fail "http cat must be byte-identical"
echo "read-only sc+http server: lazy cat byte-identical ✔"

echo
echo "RESULT: lazy by-id fetch verified (path-only fetch, offline/non-lazy gap errors, http v5)"
