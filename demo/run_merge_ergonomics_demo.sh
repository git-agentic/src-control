#!/usr/bin/env bash
# P23 demo: merge ergonomics. Proves `sc conflicts`/`sc resolve` resolve a
# conflicted merge end-to-end without hand-editing markers — first for a
# plain text conflict, then for a PROTECTED (encrypted) path where the
# base/ours/theirs view and the resolution both need `--identity` to decrypt.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

# Normalize TMPDIR the same way the other demos do: strip a trailing slash
# once so a directory-name glob sees the same base on both snapshots.
tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"

fail() { echo "FAIL: $1"; exit 1; }

work=$(mktemp -d "$tmp_base/sc-merge-ergonomics-demo.XXXXXX")
trap 'rm -rf "$work"' EXIT

keys="$work/keys"
mkdir -p "$keys"
repo="$work/repo"
mkdir -p "$repo"

# Keyless by construction, like the P15 demo: point SC_IDENTITY at a path
# that can never exist so every command is keyless unless it passes an
# explicit --identity, and any real ~/.sc/identity on the host is ignored.
export SC_IDENTITY="$work/no-such-identity"

cd "$repo"
"$SC" init >/dev/null

echo
echo "=== snapshot filesystem outside .sc/ for the zero-residue proof ==="
before=$(mktemp "$work/before.XXXXXX")
find "$tmp_base" -maxdepth 1 -name 'sc-work-*' 2>/dev/null | sort > "$before" || true

echo
echo "=== 1: set up a conflicted TEXT merge on file.txt ==="
printf 'base\n' > file.txt
"$SC" commit -m base --author demo >/dev/null
"$SC" branch feature >/dev/null

printf 'ours-line\n' > file.txt
"$SC" commit -m "main edits file.txt" --author demo >/dev/null

"$SC" switch feature >/dev/null
printf 'theirs-line\n' > file.txt
"$SC" commit -m "feature edits file.txt" --author demo >/dev/null

"$SC" switch main >/dev/null
set +e
merge_out=$("$SC" merge feature --author demo 2>&1)
merge_rc=$?
set -e
[ "$merge_rc" -eq 1 ] || fail "conflicting sc merge must exit 1, got $merge_rc"
case "$merge_out" in *"conflict"*) ;; *) fail "merge must report a conflict, got: $merge_out" ;; esac
echo "sc merge feature conflicts, exit 1 ✔"

echo
echo "=== 2: sc conflicts lists the path with its kind ==="
conflicts_out=$("$SC" conflicts)
echo "$conflicts_out"
case "$conflicts_out" in *"file.txt"*"[text]"*) ;; *) fail "expected file.txt [text] in listing, got: $conflicts_out" ;; esac
echo "sc conflicts lists file.txt [text] ✔"

echo
echo "=== 3: sc conflicts file.txt shows base/ours/theirs ==="
versions_out=$("$SC" conflicts file.txt)
echo "$versions_out"
case "$versions_out" in *"--- base ---"*) ;; *) fail "missing '--- base ---' section, got: $versions_out" ;; esac
case "$versions_out" in *"--- ours ---"*) ;; *) fail "missing '--- ours ---' section, got: $versions_out" ;; esac
case "$versions_out" in *"--- theirs ---"*) ;; *) fail "missing '--- theirs ---' section, got: $versions_out" ;; esac
case "$versions_out" in *"base"*) ;; *) fail "base content missing, got: $versions_out" ;; esac
case "$versions_out" in *"ours-line"*) ;; *) fail "ours content missing, got: $versions_out" ;; esac
case "$versions_out" in *"theirs-line"*) ;; *) fail "theirs content missing, got: $versions_out" ;; esac
echo "all three sections present, ours/theirs bytes differ (ours-line vs theirs-line) ✔"

echo
echo "=== 4: sc resolve --theirs file.txt writes clean content, no markers ==="
"$SC" resolve --theirs file.txt
[ "$(cat file.txt)" = "theirs-line" ] || fail "file.txt does not equal theirs content after resolve"
if grep -q '<<<<<<<' file.txt; then
  fail "file.txt still contains conflict markers after resolve"
fi
echo "file.txt == theirs, no <<<<<<< markers ✔"

echo
echo "=== 5: sc status shows no remaining conflicts ==="
status_out=$("$SC" status)
case "$status_out" in *"all conflicts resolved"*) ;; *) fail "expected the all-resolved status line, got: $status_out" ;; esac
case "$status_out" in *"[text]"*) fail "no per-path conflict entries should remain, got: $status_out" ;; esac
echo "sc status: no remaining conflicts ✔"

echo
echo "=== 6: sc commit completes the merge; sc log shows it ==="
"$SC" commit -m resolved --author demo >/dev/null
top_line=$("$SC" log | head -1)
case "$top_line" in *"(merge)"*) ;; *) fail "expected the merge marker on the tip commit, got: $top_line" ;; esac
echo "sc commit completed, sc log shows the merge commit ✔"

echo
echo "=== 7: PROTECTED variant — protect secret/, base commit ==="
alice_pk=$("$SC" keygen --out "$keys/alice" | grep 'public key' | awk '{print $3}')
printf '[recipients]\nalice = "%s"\n' "$alice_pk" > .sc/recipients.toml
"$SC" protect secret/ --to alice >/dev/null

mkdir -p secret
printf 'line1\n' > secret/creds.txt
"$SC" commit -m "base: protected secret/creds.txt" --author demo >/dev/null
"$SC" branch secret-feature >/dev/null

echo
echo "=== 8: diverge the SAME line on both sides so content-merge conflicts ==="
"$SC" switch secret-feature >/dev/null
printf 'feature-line\n' > secret/creds.txt
"$SC" commit -m "secret-feature edits secret/creds.txt" --author demo >/dev/null

"$SC" switch main --identity "$keys/alice" >/dev/null
[ "$(cat secret/creds.txt)" = "line1" ] || fail "main's protected file did not decrypt back to line1"
printf 'main-line\n' > secret/creds.txt
"$SC" commit -m "main edits secret/creds.txt" --author demo >/dev/null

set +e
merge_out=$("$SC" merge secret-feature --identity "$keys/alice" --author demo 2>&1)
merge_rc=$?
set -e
[ "$merge_rc" -eq 1 ] || fail "conflicting protected sc merge must exit 1, got $merge_rc"
echo "sc merge --identity alice conflicts on the protected path, exit 1 ✔"

echo
echo "=== 9: sc conflicts secret/creds.txt requires --identity, then decrypts ==="
set +e
no_identity_out=$("$SC" conflicts secret/creds.txt 2>&1)
no_identity_rc=$?
set -e
[ "$no_identity_rc" -ne 0 ] || fail "sc conflicts on a protected path without --identity should fail"
echo "keyless sc conflicts on the protected path fails as expected ✔"

kind_out=$("$SC" conflicts)
case "$kind_out" in *"secret/creds.txt"*"[protected]"*) ;; *) fail "expected secret/creds.txt [protected] in listing, got: $kind_out" ;; esac
echo "sc conflicts lists secret/creds.txt [protected] (needs --identity) ✔"

decrypted_out=$("$SC" conflicts secret/creds.txt --identity "$keys/alice")
echo "$decrypted_out"
case "$decrypted_out" in *"main-line"*) ;; *) fail "decrypted ours content missing, got: $decrypted_out" ;; esac
case "$decrypted_out" in *"feature-line"*) ;; *) fail "decrypted theirs content missing, got: $decrypted_out" ;; esac
echo "sc conflicts --identity shows decrypted plaintext base/ours/theirs ✔"

echo
echo "=== 10: sc resolve --theirs --identity resolves the protected conflict ==="
"$SC" resolve --theirs secret/creds.txt --identity "$keys/alice"
[ "$(cat secret/creds.txt)" = "feature-line" ] || fail "secret/creds.txt does not equal decrypted theirs content"
if grep -q '<<<<<<<' secret/creds.txt; then
  fail "secret/creds.txt still contains conflict markers after resolve"
fi
echo "secret/creds.txt == decrypted theirs, no markers ✔"

echo
echo "=== 11: sc commit completes the protected merge (re-encrypts, no identity needed) ==="
"$SC" commit -m "resolved protected merge" --author demo >/dev/null
top_line=$("$SC" log | head -1)
case "$top_line" in *"(merge)"*) ;; *) fail "expected the merge marker on the protected-merge tip, got: $top_line" ;; esac
echo "sc commit completed the protected merge ✔"

"$SC" switch main --identity "$keys/alice" >/dev/null
[ "$(cat secret/creds.txt)" = "feature-line" ] || fail "post-commit re-checkout does not decrypt to the resolved content"
echo "resolved content round-trips through re-encryption ✔"

echo
echo "=== 12: zero-residue proof: no leftover sc-work-* session dirs ==="
after=$(mktemp "$work/after.XXXXXX")
find "$tmp_base" -maxdepth 1 -name 'sc-work-*' 2>/dev/null | sort > "$after" || true
diff "$before" "$after" || fail "residual session directories left in $tmp_base"
echo "no residual session directories ✔"

echo
echo "RESULT: sc conflicts/sc resolve resolve a text conflict and a protected"
echo "(identity-gated, decrypted) conflict end-to-end with no hand-edited"
echo "markers; sc status/sc log/sc commit see the resolution through; zero"
echo "residue ✔"
