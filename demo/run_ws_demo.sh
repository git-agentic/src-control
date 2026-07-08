#!/usr/bin/env bash
# P20 proof: `sc ws` is a durable, multi-invocation agent session — fork,
# edit across separate `sc` process invocations, list, cumulative
# auto-merge harvest (some workspaces land, a conflicting one falls back),
# undo/redo of the landings, then manual conflict resolution of the
# fallback branch. Ends with zero `.sc/ws` residue.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

fail() { echo "FAIL: $1"; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/sc-ws-demo.XXXXXX")
trap 'rm -rf "$work"' EXIT
repo="$work/repo"
mkdir -p "$repo"
cd "$repo"

echo "=== 1: init repo, seed commit ==="
"$SC" init
printf 'alpha\n' > alpha.txt
printf 'shared\n' > shared.txt
"$SC" commit -m "base" --author demo

echo
echo "=== 2: sc ws fork --agents 3 ==="
fork_out=$("$SC" ws fork --agents 3 --author demo)
echo "$fork_out"
case "$fork_out" in *"forked 3 workspace(s)"*) ;; *) fail "fork did not report 3 workspaces: $fork_out" ;; esac

ws1_dir=""
ws2_dir=""
ws3_dir=""
while read -r idx dir; do
  case "$idx" in
    1) ws1_dir="$dir" ;;
    2) ws2_dir="$dir" ;;
    3) ws3_dir="$dir" ;;
  esac
done < <(echo "$fork_out" | tail -n +2 | awk '{print $1, $2}')
[ -n "$ws1_dir" ] && [ -n "$ws2_dir" ] && [ -n "$ws3_dir" ] \
  || fail "could not parse all three workspace dirs from fork output"
[ -d "$ws1_dir" ] || fail "workspace 1 dir missing: $ws1_dir"
[ -d "$ws2_dir" ] || fail "workspace 2 dir missing: $ws2_dir"
[ -d "$ws3_dir" ] || fail "workspace 3 dir missing: $ws3_dir"
echo "3 workspaces forked, dirs exist ✔"

echo
echo "=== 3: edit ws-1 and ws-2 disjointly; edit ws-3 to conflict with a direct main commit ==="
printf 'edited by ws-1\n' > "$ws1_dir/file-1.txt"
printf 'edited by ws-2\n' > "$ws2_dir/file-2.txt"
printf 'ws3-shared\n' > "$ws3_dir/shared.txt"

# A conflicting shared.txt edit lands directly on main AFTER the fork, so
# ws-3's eventual candidate (base = fork-time tip) conflicts with main's tip
# on shared.txt. Harvest refuses on a dirty landing tree when any workspace
# changed, so this direct edit must be committed (not left uncommitted).
printf 'main-shared\n' > shared.txt
"$SC" commit -m "main direct edit of shared.txt" --author demo

echo
echo "=== 4: sc ws list shows 3 workspaces, changed flags right ==="
list_out=$("$SC" ws list)
echo "$list_out"
case "$list_out" in *"session base: branch main"*) ;; *) fail "list missing session base line: $list_out" ;; esac
for i in 1 2 3; do
  echo "$list_out" | grep -E "^${i}[[:space:]]+changed[[:space:]]" >/dev/null \
    || fail "workspace $i not reported changed in: $list_out"
done
echo "sc ws list reports all three workspaces changed ✔"

echo
echo "=== 5: sc ws harvest — two landings, one fallback, exit 1 ==="
set +e
harvest_out=$("$SC" ws harvest --author demo)
harvest_rc=$?
set -e
echo "$harvest_out"
[ "$harvest_rc" -eq 1 ] || fail "harvest with a conflicted workspace must exit 1, got $harvest_rc"

landed_count=0
fallback_count=0
while IFS= read -r line; do
  case "$line" in
    "1  "*"landed"*) landed_count=$((landed_count + 1)) ;;
    "2  "*"landed"*) landed_count=$((landed_count + 1)) ;;
    "3  "*"fallback: branch work-3"*) fallback_count=$((fallback_count + 1)) ;;
  esac
done <<< "$harvest_out"
[ "$landed_count" -eq 2 ] || fail "expected exactly 2 landed lines, got $landed_count: $harvest_out"
[ "$fallback_count" -eq 1 ] || fail "expected exactly 1 fallback line for ws-3, got $fallback_count: $harvest_out"
echo "two landed, one fallback ✔"

log_out=$("$SC" log)
case "$log_out" in *"merge work-1"*) ;; *) fail "log missing ws-1's landing merge commit: $log_out" ;; esac
case "$log_out" in *"merge work-2"*) ;; *) fail "log missing ws-2's landing merge commit: $log_out" ;; esac
echo "sc log shows both landings on main ✔"

test -f file-1.txt || fail "ws-1's landed file missing from main"
test -f file-2.txt || fail "ws-2's landed file missing from main"
# Recursive tree walk (P21): a fixed file list would silently stop covering
# new files as the demo grows. Walk every file under the working tree,
# excluding `.sc/` (object store, refs, and — during the fallback branch's
# resolution below — legitimate in-progress MERGE_STATE bookkeeping live
# there, not in the working tree).
while IFS= read -r -d '' f; do
  grep -l "<<<<<<<" "$f" >/dev/null 2>&1 && fail "unexpected conflict marker in $f"
done < <(find "$repo" -path "$repo/.sc" -prune -o -type f -print0)
echo "no conflict markers in the working tree ✔"

echo
echo "=== 6: sc undo reverts the last landing; sc undo again redoes it ==="
tip_after_harvest=$("$SC" log | head -1 | awk '{print $1}')
test -f file-2.txt || fail "file-2.txt should exist right after harvest"

"$SC" undo
test -f file-2.txt && fail "sc undo must revert ws-2's landing (file-2.txt should be gone)"
test -f file-1.txt || fail "sc undo must not touch ws-1's landing (file-1.txt should remain)"
echo "sc undo reverted the last landing only ✔"

"$SC" undo
test -f file-2.txt || fail "second sc undo must redo ws-2's landing (file-2.txt should be back)"
tip_after_redo=$("$SC" log | head -1 | awk '{print $1}')
[ "$tip_after_redo" = "$tip_after_harvest" ] \
  || fail "redo must restore the post-harvest tip ($tip_after_harvest), got $tip_after_redo"
echo "second sc undo redid the landing, tip restored ✔"

echo
echo "=== 7: sc merge work-3 manually — markers now appear, resolve, commit ==="
set +e
merge_out=$("$SC" merge work-3 --author demo)
merge_rc=$?
set -e
[ "$merge_rc" -eq 1 ] || fail "sc merge work-3 must exit 1 on conflict, got $merge_rc"
case "$merge_out" in *"conflict"*) ;; *) fail "merge must report conflicts, got: $merge_out" ;; esac
grep -q "<<<<<<<" shared.txt || fail "expected conflict markers in shared.txt after manual merge"
echo "manual sc merge work-3 produced conflict markers (user-attended) ✔"

printf 'resolved-shared\n' > shared.txt
"$SC" commit -m "resolve work-3 conflict" --author demo
grep -q "<<<<<<<" shared.txt && fail "conflict markers must be gone after resolve+commit"
top_line=$("$SC" log | head -1)
case "$top_line" in *"resolve work-3 conflict"*) ;; *) fail "resolved commit missing from log head: $top_line" ;; esac
echo "work-3 resolved and committed ✔"

echo
echo "=== 8: zero residue — .sc/ws does not exist ==="
[ -d .sc/ws ] && fail "workspace session directory .sc/ws must not exist after the session ended"
echo "no .sc/ws residue ✔"

echo
echo "RESULT: durable multi-invocation ws session — fork/edit/list across separate"
echo "sc invocations, cumulative auto-merge harvest (2 landed, 1 fallback, exit 1),"
echo "undo/redo of the landings, manual conflict resolution of the fallback branch,"
echo "zero .sc/ws residue ✔"
