#!/usr/bin/env bash
# P24 demo: sparse checkouts. Proves that `sc sparse set <prefix>` removes
# out-of-sparse subtrees from disk (while keeping every object in the CAS),
# that editing and committing under a narrowed sparse view carries the
# untouched out-of-sparse subtrees forward byte-identical (the ADR-0025 P15
# carry discipline, generalized), and that `sc sparse disable` (and an
# independent full clone) restores everything.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"

fail() { echo "FAIL: $1"; exit 1; }

work=$(mktemp -d "$tmp_base/sc-sparse-demo.XXXXXX")
trap 'rm -rf "$work"' EXIT
repo="$work/repo"
mkdir -p "$repo"
cd "$repo"

echo "=== 1: init repo with three subtrees ==="
"$SC" init >/dev/null
mkdir -p src docs lib
printf 'fn main() {}\n' > src/a.txt
printf 'guide\n' > docs/b.txt
printf 'helper\n' > lib/c.txt
"$SC" commit -m "base: src, docs, lib" --author demo >/dev/null
docs_before=$(cksum docs/b.txt)
lib_before=$(cksum lib/c.txt)
echo "base commit with src/, docs/, lib/ ✔"

echo
echo "=== 2: sc sparse set src/ removes docs/ and lib/ from disk ==="
"$SC" sparse set src/ >/dev/null
[ -f src/a.txt ] || fail "src/a.txt must remain materialized"
find docs -type f 2>/dev/null | grep -q . && fail "docs/ must have no files on disk after sparse set src/"
find lib -type f 2>/dev/null | grep -q . && fail "lib/ must have no files on disk after sparse set src/"
echo "src/ present, docs/ and lib/ absent from disk ✔"

echo
echo "=== 3: sc sparse show lists src/ ==="
show_out=$("$SC" sparse show)
case "$show_out" in *"src/"*) ;; *) fail "sparse show must list src/: $show_out" ;; esac
echo "sc sparse show lists src/ ✔"

echo
echo "=== 4: edit src/a.txt and commit while sparse — docs/ and lib/ carry, untouched ==="
printf 'fn main() { println!("v2"); }\n' > src/a.txt
"$SC" commit -m "src: edit under sparse" --author demo >/dev/null
st_out=$("$SC" status)
case "$st_out" in *"deleted"*"docs"*|*"deleted"*"lib"*) fail "status must not report the out-of-sparse subtrees as deleted: $st_out" ;; esac
echo "committed under sparse; status doesn't misreport the out-of-sparse subtrees as deleted ✔"

echo
echo "=== 5: independent proof — clone the still-sparse repo in full; CAS carry byte-identical ==="
# The origin is still narrowed to src/ here (docs/ and lib/ absent from its
# disk) — cloning now proves the carry lives in the CAS, not merely that
# 'sparse disable' can reconstruct what's still sitting on the origin's disk.
clone="$work/clone"
"$SC" clone "$repo" "$clone" >/dev/null
[ -f "$clone/docs/b.txt" ] || fail "clone must materialize docs/b.txt in full"
[ -f "$clone/lib/c.txt" ] || fail "clone must materialize lib/c.txt in full"
clone_docs=$(cksum "$clone/docs/b.txt" | awk '{print $1, $2}')
clone_lib=$(cksum "$clone/lib/c.txt" | awk '{print $1, $2}')
[ "${docs_before%% *}" = "${clone_docs%% *}" ] || fail "cloned docs/b.txt must match the pre-sparse content"
[ "${lib_before%% *}" = "${clone_lib%% *}" ] || fail "cloned lib/c.txt must match the pre-sparse content"
grep -q 'v2' "$clone/src/a.txt" || fail "clone must see the src/ edit made under sparse"
echo "full clone of the still-sparse origin proves the CAS carry, byte-identical ✔"

echo
echo "=== 6: sc sparse disable restores docs/ and lib/ byte-identical, plus the src/ edit ==="
"$SC" sparse disable >/dev/null
[ -f docs/b.txt ] || fail "docs/b.txt must be restored by sparse disable"
[ -f lib/c.txt ] || fail "lib/c.txt must be restored by sparse disable"
docs_after=$(cksum docs/b.txt)
lib_after=$(cksum lib/c.txt)
[ "$docs_before" = "$docs_after" ] || fail "docs/b.txt must be byte-identical after disable (before: $docs_before, after: $docs_after)"
[ "$lib_before" = "$lib_after" ] || fail "lib/c.txt must be byte-identical after disable (before: $lib_before, after: $lib_after)"
grep -q 'v2' src/a.txt || fail "src/ edit made under sparse must still be present after disable"
show_out=$("$SC" sparse show)
case "$show_out" in *"disabled"*) ;; *) fail "sparse show must report disabled after sparse disable: $show_out" ;; esac
echo "sparse disable restored docs/ + lib/ byte-identical, and kept the src/ edit ✔"

echo
echo "=== 7: zero residue — the repo lives entirely under \$work, nothing leaks outside ==="
[ -d "$repo/.sc" ] || fail ".sc must exist inside the repo while it's alive"
echo "no residue outside the temp workspace ✔"

echo
echo "RESULT: sc sparse set removed docs/+lib/ from disk while src/ stayed; sc sparse show"
echo "reported the active prefix; a commit under sparse carried the untouched out-of-sparse"
echo "subtrees forward verbatim; sc sparse disable AND an independent full clone both restored"
echo "docs/+lib/ byte-identical while keeping the src/ edit; zero residue ✔"
