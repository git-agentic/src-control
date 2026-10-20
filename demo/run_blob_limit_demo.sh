#!/usr/bin/env bash
# P27 follow-on demo: blob-size clone filter (ADR-0055, #217). Proves that
# `sc clone --filter blob:limit=<size>` leaves large OLD blobs out of the
# transfer while every ref tip stays complete (the checkout is whole), that
# `sc verify` / `sc gc` / `sc push` work on such a clone, that `sc backfill
# <path>` repairs the gap, that `--lazy` is accepted with only a size filter,
# that a prefix filter combines with a size limit, and that a later `sc fetch`
# keeps the limit (tips stay complete) unless `--no-blob-limit` is given.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

fail() { echo "FAIL: $1"; exit 1; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

objects() { find "$1/.sc/objects" -type f | wc -l | tr -d ' '; }

ORIGIN="$W/origin"
mkdir -p "$ORIGIN"
(
  cd "$ORIGIN"
  "$SC" init >/dev/null
  mkdir -p src
  head -c 65536 /dev/urandom | od -An -tx1 | tr -d ' \n' > assets.bin   # v1, ~128 KiB
  printf 'fn main() {}\n' > src/a.txt
  "$SC" commit -m "v1" --author demo >/dev/null
  head -c 65536 /dev/urandom | od -An -tx1 | tr -d ' \n' > assets.bin   # v2
  printf 'fn main() { 2 }\n' > src/a.txt
  "$SC" commit -m "v2" --author demo >/dev/null
)
FULL=$(objects "$ORIGIN")
echo "origin: two versions of a ~128 KiB assets.bin; $FULL object(s) ✔"

echo
echo "=== 1: blob:limit=16KiB leaves the old assets.bin out, the checkout is whole ==="
LIM="$W/limited"
"$SC" clone --filter blob:limit=16KiB "$ORIGIN" "$LIM" > "$W/clone.out"
grep -q "partial: blob:limit=16384" "$W/clone.out" || fail "clone must report the limit: $(cat "$W/clone.out")"
[ "$(objects "$LIM")" -lt "$FULL" ] || fail "the limited clone must hold fewer objects than the origin"
cmp "$LIM/assets.bin" "$ORIGIN/assets.bin" || fail "the tip's large file must be checked out byte-identically"
[ -f "$LIM/.sc/promisor-blob-limit" ] || fail "the clone must record its limit"
echo "$(objects "$LIM") of $FULL object(s); tip assets.bin materialized ✔"

echo
echo "=== 2: verify reports the gap as expected, gc and status are happy ==="
(cd "$LIM" && "$SC" verify) > "$W/verify.out"
grep -q "partial: 1 object(s) outside filter \[blob:limit=16384\]" "$W/verify.out" || fail "verify gap line: $(cat "$W/verify.out")"
(cd "$LIM" && "$SC" gc >/dev/null && "$SC" status >/dev/null)
echo "verify: 1 gap (the old assets.bin), gc + status fine ✔"

echo
echo "=== 3: a commit pushes back; the origin keeps the history ==="
(cd "$LIM" && printf 'fn main() { 3 }\n' > src/a.txt && "$SC" commit -m "v3" --author demo >/dev/null && "$SC" push origin >/dev/null)
(cd "$ORIGIN" && "$SC" log | grep -q "v3") || fail "the origin must have the pushed commit"
echo "push from the limited clone landed ✔"

echo
echo "=== 4: --lazy is accepted when the only filter is blob: ==="
LAZY="$W/lazy"
"$SC" clone --filter blob:limit=16KiB --lazy "$ORIGIN" "$LAZY" >/dev/null
[ -f "$LAZY/.sc/promisor-lazy" ] || fail "--lazy must work with only a blob: filter"
echo "lazy marker set on a size-only clone ✔"

echo
echo "=== 5: a prefix filter combines with the limit ==="
COMBO="$W/combo"
"$SC" clone --filter src/ --filter blob:limit=16KiB "$ORIGIN" "$COMBO" > "$W/combo.out"
grep -q "partial: src/, blob:limit=16384" "$W/combo.out" || fail "combo report: $(cat "$W/combo.out")"
[ ! -e "$COMBO/assets.bin" ] || fail "assets.bin is outside the prefix and must not be materialized"
echo "src/ + blob:limit: scope first, limit second ✔"

echo
echo "=== 6: grammar errors are actionable ==="
if "$SC" clone --filter blob:none "$ORIGIN" "$W/bad" 2>"$W/bad.err"; then fail "blob:none must be rejected"; fi
grep -q "blob:limit=0" "$W/bad.err" || fail "blob:none error must point at blob:limit=0: $(cat "$W/bad.err")"
echo "blob:none -> use blob:limit=0 ✔"

echo
echo "=== 7: backfill by the file's own path, then --all ==="
(cd "$LIM" && "$SC" backfill assets.bin >/dev/null)
(cd "$LIM" && "$SC" verify) | grep -q "partial: 0 object(s)" || fail "backfill must close the gap"
(cd "$LIM" && "$SC" backfill --all >/dev/null)
[ ! -e "$LIM/.sc/promisor" ] && [ ! -e "$LIM/.sc/promisor-blob-limit" ] || fail "--all must remove both markers"
echo "backfill assets.bin closed the gap; --all made it a full clone ✔"

echo
echo "=== 8: sc fetch keeps the limit; --no-blob-limit opts out for one fetch ==="
KEEP="$W/keep"; FULLF="$W/fullf"
"$SC" clone --filter blob:limit=16KiB "$ORIGIN" "$KEEP" >/dev/null
"$SC" clone --filter blob:limit=16KiB "$ORIGIN" "$FULLF" >/dev/null
(
  cd "$ORIGIN"
  head -c 65536 /dev/urandom | od -An -tx1 | tr -d ' \n' > assets.bin   # v4: history only after v5
  "$SC" commit -m "v4" --author demo >/dev/null
  head -c 65536 /dev/urandom | od -An -tx1 | tr -d ' \n' > assets.bin   # v5: the new tip
  "$SC" commit -m "v5" --author demo >/dev/null
)
(cd "$KEEP" && "$SC" fetch >/dev/null && "$SC" merge origin/main >/dev/null)
(cd "$FULLF" && "$SC" fetch --no-blob-limit >/dev/null && "$SC" merge origin/main >/dev/null)
cmp "$KEEP/assets.bin" "$ORIGIN/assets.bin" || fail "the fetched tip's large file must be whole"
(cd "$KEEP" && "$SC" verify) | grep -q "partial: 2 object(s) outside filter \[blob:limit=16384\]" || fail "fetch must leave v4 out: $(cd "$KEEP" && "$SC" verify)"
(cd "$FULLF" && "$SC" verify) | grep -q "partial: 1 object(s) outside filter \[blob:limit=16384\]" || fail "--no-blob-limit must fetch v4: $(cd "$FULLF" && "$SC" verify)"
[ -f "$FULLF/.sc/promisor-blob-limit" ] || fail "--no-blob-limit must keep the recorded limit"
echo "plain fetch: v4 left out, tip whole; --no-blob-limit: v4 arrived, marker kept ✔"

echo
echo "RESULT: blob-size clone filter proven (limit, tips complete, verify/gc/push, lazy marker, combo, repair, limit-aware fetch)"
