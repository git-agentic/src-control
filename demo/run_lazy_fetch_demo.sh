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
HTTP_BEFORE=$(objects "$HTTP")
(cd "$HTTP" && "$SC" cat main:docs/api/guide.bin) > "$W/http.out"
cmp "$W/http.out" "$ORIGIN/docs/api/guide.bin" || fail "http cat must be byte-identical"
[ "$(($(objects "$HTTP") - HTTP_BEFORE))" -eq 3 ] || fail "http cat must fetch exactly 3 objects, got $(($(objects "$HTTP") - HTTP_BEFORE))"
[ "$(objects "$HTTP")" -lt "$FULL" ] || fail "http cat must leave the sibling blob unfetched"
echo "read-only sc+http server: lazy cat byte-identical, +3 objects, sibling not fetched ✔"

echo
echo "=== 8: widen the view past the filter, commit, push, undo offline (ADR-0048) ==="
WIDE="$W/wide"
"$SC" clone --filter src/ --lazy "$ORIGIN" "$WIDE" >/dev/null
[ ! -e "$WIDE/docs" ] || fail "docs/ must not be on disk before the widen"
# Offline, the widen is refused before anything changes: the spec stays put.
SPEC_BEFORE=$(cat "$WIDE/.sc/sparse")
if (cd "$WIDE" && SC_OFFLINE=1 "$SC" sparse set src/ docs/) >/dev/null 2>"$W/wide-off.err"; then
  fail "an offline widen of a lazy clone must fail"
fi
[ "$(cat "$WIDE/.sc/sparse")" = "$SPEC_BEFORE" ] || fail "a refused widen must leave .sc/sparse unchanged"
[ ! -e "$WIDE/docs" ] || fail "a refused widen must write nothing"
echo "offline widen: refused, .sc/sparse unchanged, nothing written ✔"
# Online, it fills the closure by id and lays the files out.
(cd "$WIDE" && "$SC" sparse set src/ docs/ >/dev/null)
cmp "$WIDE/docs/api/guide.bin" "$ORIGIN/docs/api/guide.bin" || fail "widened file must be byte-identical"
cmp "$WIDE/docs/api/other.bin" "$ORIGIN/docs/api/other.bin" || fail "the whole docs/ closure must be filled"
echo "sparse set src/ docs/: closure filled, files byte-identical ✔"
printf 'edited from a widened view\n' > "$WIDE/docs/api/guide.bin"
(cd "$WIDE" && "$SC" commit -m "edit docs" --author demo >/dev/null && "$SC" push origin >/dev/null)
SECOND="$W/second"
"$SC" clone "$ORIGIN" "$SECOND" >/dev/null
[ "$(cat "$SECOND/docs/api/guide.bin")" = "edited from a widened view" ] || fail "a second clone must see the edit"
echo "commit + push from the widened view: a second clone sees it ✔"
(cd "$WIDE" && "$SC" gc >/dev/null) || fail "gc must work after a widen"
(cd "$WIDE" && "$SC" verify >/dev/null) || fail "verify must work after a widen"
echo "gc and verify after the widen ✔"
# The closure is present, so undo needs no network even with the origin gone.
mv "$ORIGIN" "$ORIGIN.gone"
(cd "$WIDE" && SC_OFFLINE=1 "$SC" undo >/dev/null) || fail "undo of the commit must work offline"
# The origin working tree still holds the pre-edit file (a push moves refs only).
cmp "$WIDE/docs/api/guide.bin" "$ORIGIN.gone/docs/api/guide.bin" || fail "undo must restore the pre-edit file"
mv "$ORIGIN.gone" "$ORIGIN"
echo "undo after a widen, offline ✔"

echo
echo "=== 9: merge on a partial clone carries the other side's region unread (ADR-0049) ==="
MORIGIN="$W/morigin"
mkdir -p "$MORIGIN"
(
  cd "$MORIGIN"
  "$SC" init >/dev/null
  mkdir -p src docs/api
  printf 'one\ntwo\nthree\n' > src/a.txt
  printf 'guide\n' > docs/api/guide.md
  head -c 65536 /dev/urandom | od -An -tx1 | tr -d ' \n' > docs/api/big.bin
  "$SC" commit -m "base" --author demo >/dev/null
  "$SC" branch feature
  "$SC" switch feature >/dev/null
  head -c 65536 /dev/urandom | od -An -tx1 | tr -d ' \n' > docs/api/big.bin
  cp docs/api/big.bin "$W/feature-big.bin"
  "$SC" commit -m "feature edits docs" --author demo >/dev/null
  "$SC" switch main >/dev/null
)
MERGE="$W/merge"
"$SC" clone --filter src/ --lazy "$MORIGIN" "$MERGE" >/dev/null
printf 'one\nTWO\nthree\n' > "$MERGE/src/a.txt"
(cd "$MERGE" && "$SC" commit -m "local src edit" --author demo >/dev/null && "$SC" fetch origin >/dev/null)
MBEFORE=$(objects "$MERGE")
(cd "$MERGE" && "$SC" merge origin/feature --author demo >/dev/null) || fail "disjoint merge on a partial clone must succeed"
[ ! -e "$MERGE/docs" ] || fail "docs/ is outside the view and must not be written"
[ "$(cat "$MERGE/src/a.txt")" = "$(printf 'one\nTWO\nthree')" ] || fail "the local src edit must survive the merge"
MAFTER=$(objects "$MERGE")
# The merge commit and the merged root/src trees are new; the 64 KiB docs blob is not.
[ "$(($MAFTER - $MBEFORE))" -le 4 ] || fail "a disjoint merge must not fetch the other side's region ($MBEFORE -> $MAFTER)"
echo "disjoint merge on a lazy partial clone: docs/ untouched and unfetched ($MBEFORE -> $MAFTER objects) ✔"
(cd "$MERGE" && "$SC" push origin >/dev/null) || fail "pushing the merge must work"
MFULL="$W/merge-full"
"$SC" clone "$MORIGIN" "$MFULL" >/dev/null
[ "$(cat "$MFULL/src/a.txt")" = "$(printf 'one\nTWO\nthree')" ] || fail "a full re-clone must see the local edit"
cmp "$MFULL/docs/api/big.bin" "$W/feature-big.bin" || fail "the merge must carry feature's docs blob byte-identical"
echo "push + full re-clone: merged result has both sides, docs byte-identical ✔"

echo
echo "=== 10: a conflict inside the view resolves and completes without the other side's region (ADR-0049) ==="
CORIGIN="$W/corigin"
mkdir -p "$CORIGIN"
(
  cd "$CORIGIN"
  "$SC" init >/dev/null
  mkdir -p src docs/api
  printf 'one\ntwo\nthree\n' > src/a.txt
  printf 'guide\n' > docs/api/guide.md
  head -c 65536 /dev/urandom | od -An -tx1 | tr -d ' \n' > docs/api/big.bin
  "$SC" commit -m "base" --author demo >/dev/null
  "$SC" branch feature
  "$SC" switch feature >/dev/null
  printf 'ONE\ntwo\nthree\n' > src/a.txt
  head -c 65536 /dev/urandom | od -An -tx1 | tr -d ' \n' > docs/api/big.bin
  cp docs/api/big.bin "$W/conflict-feature-big.bin"
  "$SC" commit -m "feature edits src and docs" --author demo >/dev/null
  "$SC" switch main >/dev/null
)
CONFLICT="$W/conflict"
"$SC" clone --filter src/ --lazy "$CORIGIN" "$CONFLICT" >/dev/null
printf 'uno\ntwo\nthree\n' > "$CONFLICT/src/a.txt"
(cd "$CONFLICT" && "$SC" commit -m "local src edit" --author demo >/dev/null && "$SC" fetch origin >/dev/null)
CBEFORE=$(objects "$CONFLICT")
if (cd "$CONFLICT" && "$SC" merge origin/feature --author demo >/dev/null 2>&1); then
  fail "a conflicting merge must stop for resolution"
fi
grep -q '<<<<<<<' "$CONFLICT/src/a.txt" || fail "markers must be written in the view"
[ ! -e "$CONFLICT/docs" ] || fail "docs/ is outside the view and must not be written"
(cd "$CONFLICT" && "$SC" conflicts | grep -q 'src/a.txt') || fail "sc conflicts must list the path"
(cd "$CONFLICT" && "$SC" resolve --ours src/a.txt >/dev/null) || fail "sc resolve must work on a partial clone"
(cd "$CONFLICT" && "$SC" commit -m "merge feature" --author demo >/dev/null) || fail "completing the merge must work"
CAFTER=$(objects "$CONFLICT")
[ "$(($CAFTER - $CBEFORE))" -le 6 ] || fail "a conflict in the view must not fetch the other side's region ($CBEFORE -> $CAFTER)"
echo "conflict in src/ resolved and committed, docs/ unwritten and unfetched ($CBEFORE -> $CAFTER objects) ✔"
(cd "$CONFLICT" && "$SC" push origin >/dev/null) || fail "pushing the merge must work"
CFULL="$W/conflict-full"
"$SC" clone "$CORIGIN" "$CFULL" >/dev/null
[ "$(cat "$CFULL/src/a.txt")" = "$(printf 'uno\ntwo\nthree')" ] || fail "the resolution must be the merged result"
cmp "$CFULL/docs/api/big.bin" "$W/conflict-feature-big.bin" || fail "feature's docs blob must be carried byte-identical"
echo "push + full re-clone: resolution and carried docs both present ✔"

echo
echo "RESULT: lazy by-id fetch verified (path-only fetch, offline/non-lazy gap errors, http v5, widen/commit/push/undo, merge, conflict)"
