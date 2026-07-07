#!/usr/bin/env bash
# P14 proof: cherry-pick, rebase, and undo/redo round-trip on branches minted
# by `sc work`, plus the oplog that makes it all reversible.
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

work=$(mktemp -d "$tmp_base/sc-history-demo.XXXXXX")
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
echo "=== snapshot the filesystem outside .sc/ (before sc work sessions) ==="
before=$(mktemp "$work/before.XXXXXX")
find "$tmp_base" -maxdepth 1 -name 'sc-work-*' 2>/dev/null | sort > "$before" || true

echo
echo "=== 1: sc work forks 3 agents, each edits a distinct file ==="
"$SC" work --agents 3 --author demo -- \
  sh -c 'echo "edited by $SC_WORKSPACE" > "file-$SC_WORKSPACE.txt"'
for i in 1 2 3; do
  test -f ".sc/refs/heads/work-$i" || fail "missing branch work-$i"
done
echo "3 branches minted ✔"

echo
echo "=== 2: sc merge work-1 ==="
"$SC" merge work-1 --author demo
test -f file-work-1.txt || fail "work-1's edit missing after merge"
echo "merge clean ✔"

echo
echo "=== 3: sc cherry-pick work-2 ==="
"$SC" cherry-pick work-2 --author demo
test -f file-work-2.txt || fail "work-2's edit missing after cherry-pick"
"$SC" log | head -1 | grep -q '(cherry-picked from' \
  || fail "log head message missing '(cherry-picked from' marker"
echo "cherry-pick recorded provenance ✔"

echo
echo "=== 4: sc switch work-3 && sc rebase main ==="
"$SC" switch work-3

echo "--- snapshot .sc/refs pre-rebase ---"
pre_rebase="$work/refs-pre-rebase"
cp -R .sc/refs "$pre_rebase"

"$SC" rebase main --author demo
test -f file-work-1.txt || fail "main's work-1 merge missing from rebased tree"
test -f file-work-2.txt || fail "main's work-2 cherry-pick missing from rebased tree"
test -f file-work-3.txt || fail "work-3's edit missing after rebase"
top_line=$("$SC" log | head -1)
echo "$top_line" | grep -q '(merge)' \
  && fail "rebased tip should be linear (single-parent), not a merge commit"
echo "work-3 rebased atop main (main's content present), linear history ✔"

echo "--- snapshot .sc/refs post-rebase ---"
post_rebase="$work/refs-post-rebase"
cp -R .sc/refs "$post_rebase"

echo
echo "=== 5: sc undo restores pre-rebase refs ==="
"$SC" undo
diff -r "$pre_rebase" .sc/refs || fail "refs after undo do not match pre-rebase snapshot"
echo "undo restored pre-rebase refs byte-for-byte ✔"

echo
echo "=== 6: sc undo again redoes the rebase ==="
"$SC" undo
diff -r "$post_rebase" .sc/refs || fail "refs after second undo (redo) do not match post-rebase snapshot"
echo "second undo redid the rebase, refs byte-for-byte ✔"

echo
echo "=== 7: sc oplog lists operations newest-first ==="
oplog_out=$("$SC" oplog)
echo "$oplog_out"
first_seq=$(echo "$oplog_out" | head -1 | awk '{print $1}')
last_seq=$(echo "$oplog_out" | tail -1 | awk '{print $1}')
test "$first_seq" -gt "$last_seq" || fail "oplog is not newest-first (first seq $first_seq <= last seq $last_seq)"
echo "oplog newest-first ✔"

echo
echo "=== 8: zero-residue proof: no leftover sc-work-* session dirs ==="
after=$(mktemp "$work/after.XXXXXX")
find "$tmp_base" -maxdepth 1 -name 'sc-work-*' 2>/dev/null | sort > "$after" || true
diff "$before" "$after" || fail "residual session directories left in $tmp_base"
echo "no residual session directories ✔"

echo
echo "=== 9: resumable rebase — stop, resolve, --continue, ONE oplog record, undo ==="
"$SC" switch main
"$SC" branch stop-demo
"$SC" switch stop-demo
printf 'alpha\nfeature-line\n' > alpha.txt
"$SC" commit -m "stop-demo edits alpha" --author demo
pre_rebase_tip=$("$SC" log | head -1 | awk '{print $1}')

"$SC" switch main
printf 'alpha\nmain-line\n' > alpha.txt
"$SC" commit -m "main edits alpha" --author demo
"$SC" switch stop-demo

ops_before=$("$SC" oplog | wc -l | tr -d ' ')

set +e
rebase_out=$("$SC" rebase main --author demo 2>&1)
rebase_rc=$?
set -e
[ "$rebase_rc" -eq 1 ] || fail "conflicting sc rebase must exit 1, got $rebase_rc"
case "$rebase_out" in *"rebase stopped at"*) ;; *) fail "rebase must report a stop, got: $rebase_out" ;; esac
echo "rebase stopped on conflict, exit 1 ✔"

status_out=$("$SC" status)
case "$status_out" in *"rebase in progress"*) ;; *) fail "sc status must report the stopped rebase, got: $status_out" ;; esac
echo "sc status reports the stop ✔"

printf 'alpha\nresolved-line\n' > alpha.txt
"$SC" rebase --continue --author demo >/dev/null
ops_after=$("$SC" oplog | wc -l | tr -d ' ')
test "$((ops_after - ops_before))" -eq 1 \
  || fail "expected exactly ONE new oplog record for the stop-and-continue rebase, got $((ops_after - ops_before))"
echo "sc rebase --continue completed the rebase, exactly ONE oplog record ✔"

status_out=$("$SC" status)
case "$status_out" in *"rebase in progress"*) fail "rebase state must be cleared after completion" ;; esac

"$SC" undo >/dev/null
post_undo_tip=$("$SC" log | head -1 | awk '{print $1}')
[ "$post_undo_tip" = "$pre_rebase_tip" ] \
  || fail "sc undo must restore the pre-rebase tip ($pre_rebase_tip), got $post_undo_tip"
echo "sc undo restored the pre-rebase tip ✔"

echo
echo "=== 10: aborted cherry-pick — byte-identical tree, no pick state left behind ==="
"$SC" switch main
"$SC" branch pick-source
"$SC" switch pick-source
printf 'beta\npick-line\n' > beta.txt
"$SC" commit -m "pick-source edits beta" --author demo
"$SC" switch main
printf 'beta\nmain-beta-line\n' > beta.txt
"$SC" commit -m "main edits beta" --author demo

before_sum=$(cksum beta.txt)

set +e
pick_out=$("$SC" cherry-pick pick-source --author demo 2>&1)
pick_rc=$?
set -e
[ "$pick_rc" -eq 1 ] || fail "conflicting sc cherry-pick must exit 1, got $pick_rc"
case "$pick_out" in *"conflict"*) ;; *) fail "cherry-pick must report conflicts, got: $pick_out" ;; esac

status_out=$("$SC" status)
case "$status_out" in *"cherry-pick in progress"*) ;; *) fail "sc status must report the pick in progress, got: $status_out" ;; esac

"$SC" cherry-pick --abort
after_sum=$(cksum beta.txt)
[ "$before_sum" = "$after_sum" ] \
  || fail "aborted cherry-pick must restore beta.txt byte-identical (before: $before_sum, after: $after_sum)"
echo "sc cherry-pick --abort restored the tree byte-identical ✔"

status_out=$("$SC" status)
case "$status_out" in *"cherry-pick in progress"*) fail "pick state must be cleared after --abort" ;; esac
echo "no cherry-pick state left behind ✔"

echo
echo "=== 11: sc amend fixes the tip message, history length unchanged ==="
printf 'gamma\n' > gamma.txt
"$SC" commit -m "gamma: tyop in this message" --author demo
hist_before=$("$SC" log | wc -l | tr -d ' ')

"$SC" amend -m "gamma: fixed message" --author demo >/dev/null
hist_after=$("$SC" log | wc -l | tr -d ' ')
[ "$hist_before" = "$hist_after" ] \
  || fail "sc amend must not change history length (before: $hist_before, after: $hist_after)"

top_line=$("$SC" log | head -1)
case "$top_line" in *"gamma: fixed message"*) ;; *) fail "amended message missing from log head, got: $top_line" ;; esac
case "$top_line" in *"tyop"*) fail "old (pre-amend) message must not still be the tip message, got: $top_line" ;; esac
echo "sc amend replaced the tip message, history length unchanged ✔"

echo
echo "RESULT: cherry-pick provenance, atomic rebase, undo/redo round-trip, oplog newest-first,"
echo "resumable rebase (stop/continue/ONE oplog record/undo), aborted cherry-pick (byte-identical"
echo "tree), sc amend (message fixed, history length unchanged), zero residue ✔"
