#!/usr/bin/env bash
# P15 demo: protected merge & replay. Proves that merges/rebases/cherry-picks
# involving protected (encrypted) paths need NO identity when the protected
# edits are disjoint, but need an explicit --identity when the same protected
# path diverges in content on both sides — and that once an identity resolves
# the merge, every recipient of the path (not just the one who supplied the
# key) can still decrypt the result. Also proves secret-registry replay
# through rebase, and that an unauthorized clone never sees protected
# plaintext.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

# Normalize TMPDIR the same way run_history_demo.sh does: strip a trailing
# slash once so a directory-name glob sees the same base on both snapshots.
tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"

fail() { echo "FAIL: $1"; exit 1; }

work=$(mktemp -d "$tmp_base/sc-protected-merge-demo.XXXXXX")
trap 'rm -rf "$work"' EXIT

keys="$work/keys"
mkdir -p "$keys"
repo="$work/repo"
mkdir -p "$repo"

# Keyless by construction: point SC_IDENTITY at a path that can never exist,
# so every command below is keyless UNLESS it passes an explicit --identity.
# This also neutralizes any real ~/.sc/identity on the host running the demo.
export SC_IDENTITY="$work/no-such-identity"

echo "=== setup: repo, alice + bob identities, protect secret/, base commit ==="
alice_pk=$("$SC" keygen --out "$keys/alice" | grep 'public key' | awk '{print $3}')
bob_pk=$("$SC" keygen --out "$keys/bob" | grep 'public key' | awk '{print $3}')

cd "$repo"
"$SC" init >/dev/null
printf '[recipients]\nalice = "%s"\nbob = "%s"\n' "$alice_pk" "$bob_pk" > .sc/recipients.toml
"$SC" protect secret/ --to alice,bob >/dev/null

mkdir -p secret
printf 'url=host1\ntoken=tok0\n' > secret/creds.txt
"$SC" commit -m "base: protected secret/creds.txt" --author demo >/dev/null

echo
echo "=== snapshot filesystem outside .sc/ for the zero-residue proof ==="
before=$(mktemp "$work/before.XXXXXX")
find "$tmp_base" -maxdepth 1 -name 'sc-work-*' 2>/dev/null | sort > "$before" || true

echo
echo "=== 1: two branches with DISJOINT protected edits merge with NO identity ==="
"$SC" branch topic-a >/dev/null
"$SC" switch topic-a >/dev/null
printf 'alice-data\n' > secret/a.txt
"$SC" commit -m "topic-a: add secret/a.txt" --author demo >/dev/null

"$SC" switch main >/dev/null
"$SC" branch topic-b >/dev/null
"$SC" switch topic-b >/dev/null
printf 'bob-data\n' > secret/b.txt
"$SC" commit -m "topic-b: add secret/b.txt" --author demo >/dev/null

"$SC" switch topic-a >/dev/null
"$SC" merge topic-b --author demo >/dev/null \
  || fail "keyless merge of disjoint protected edits (topic-b into topic-a) should succeed"
echo "keyless merge of disjoint protected edits succeeded ✔"

# secret/b.txt is new content introduced by the merge: with no identity it is
# skipped on disk (never written as ciphertext or plaintext).
[ -f secret/b.txt ] && fail "keyless merge materialized secret/b.txt without a key"
echo "secret/b.txt correctly skipped (no key) after keyless merge ✔"

"$SC" switch topic-a --identity "$keys/alice" >/dev/null
[ "$(cat secret/a.txt)" = "alice-data" ] || fail "alice: secret/a.txt did not decrypt correctly"
[ "$(cat secret/b.txt)" = "bob-data" ] || fail "alice: secret/b.txt did not decrypt correctly"
echo "alice's identity materializes both disjoint protected edits decrypted ✔"

"$SC" switch topic-a --identity "$keys/bob" >/dev/null
[ "$(cat secret/a.txt)" = "alice-data" ] || fail "bob: secret/a.txt did not decrypt correctly"
[ "$(cat secret/b.txt)" = "bob-data" ] || fail "bob: secret/b.txt did not decrypt correctly"
echo "bob's identity materializes both disjoint protected edits decrypted ✔"

# Fold topic-a (which now carries both disjoint edits) back into main.
"$SC" switch main --identity "$keys/alice" >/dev/null
"$SC" merge topic-a --identity "$keys/alice" --author demo >/dev/null \
  || fail "folding topic-a back into main should succeed"

echo
echo "=== 2: colliding protected edits on fresh branches ==="
"$SC" branch col-a >/dev/null
"$SC" switch col-a >/dev/null
printf 'url=host-a\ntoken=tok0\n' > secret/creds.txt
"$SC" commit -m "col-a: change url" --author demo >/dev/null

"$SC" switch main >/dev/null
"$SC" branch col-b >/dev/null
"$SC" switch col-b >/dev/null
printf 'url=host1\ntoken=tok-b\n' > secret/creds.txt
"$SC" commit -m "col-b: change token" --author demo >/dev/null

"$SC" switch col-a >/dev/null
merge_err="$(mktemp "$work/merge-err.XXXXXX")"
if "$SC" merge col-b --author demo >/dev/null 2>"$merge_err"; then
  fail "keyless merge of colliding protected edits should have failed"
fi
grep -q "changed on both sides; re-run with --identity" "$merge_err" \
  || fail "merge failure did not report the needs-identity error (got: $(cat "$merge_err"))"
echo "keyless merge of colliding protected edits fails with the needs-identity error ✔"

"$SC" merge col-b --identity "$keys/alice" --author demo >/dev/null \
  || fail "sc merge --identity alice should resolve the colliding protected merge"
[ "$(cat secret/creds.txt)" = "$(printf 'url=host-a\ntoken=tok-b\n')" ] \
  || fail "merged secret/creds.txt does not carry both sides' line-level edits"
echo "sc merge --identity alice merges the colliding content cleanly ✔"

"$SC" switch col-a --identity "$keys/bob" >/dev/null
[ "$(cat secret/creds.txt)" = "$(printf 'url=host-a\ntoken=tok-b\n')" ] \
  || fail "bob could not decrypt the identity-merged secret/creds.txt"
echo "bob decrypts the identity-resolved merge result ✔"

"$SC" switch main --identity "$keys/alice" >/dev/null
"$SC" merge col-a --identity "$keys/alice" --author demo >/dev/null \
  || fail "folding col-a back into main should succeed"

echo
echo "=== 3: secret registry replay through rebase ==="
"$SC" branch topic-secret >/dev/null
"$SC" switch topic-secret >/dev/null
"$SC" secret add TOKEN --to alice --value 's3cr3t-token' >/dev/null

# Advance main independently (unprotected, disjoint file) so the rebase is a
# real replay, not a no-op fast-forward.
"$SC" switch main --identity "$keys/alice" >/dev/null
printf 'unrelated notes\n' > notes.txt
"$SC" commit -m "main: unrelated notes.txt" --author demo >/dev/null

"$SC" switch topic-secret >/dev/null
"$SC" rebase main >/dev/null \
  || fail "keyless rebase of a disjoint secrets-only commit onto main should succeed"
echo "keyless rebase (secrets-only commit, disjoint from main's file edit) succeeded ✔"

"$SC" secret list | grep -q '^TOKEN ' \
  || fail "TOKEN missing from 'sc secret list' at the rebased tip"
echo "TOKEN present in the secret registry at the rebased tip ✔"

echo
echo "=== 4: unauthorized clone never materializes protected plaintext ==="
clone="$work/clone"
"$SC" clone "$repo" "$clone" >/dev/null

[ -f "$clone/secret/creds.txt" ] && fail "unauthorized clone materialized secret/creds.txt"
[ -f "$clone/secret/a.txt" ] && fail "unauthorized clone materialized secret/a.txt"
[ -f "$clone/secret/b.txt" ] && fail "unauthorized clone materialized secret/b.txt"
echo "unauthorized clone's working tree has no protected files ✔"

if grep -qsr -e "host-a" -e "tok-b" -e "alice-data" -e "bob-data" -e "s3cr3t-token" "$clone" \
    --exclude-dir=.sc; then
  fail "protected plaintext leaked into the unauthorized clone's working tree"
fi
echo "no protected plaintext found anywhere in the unauthorized clone's working tree ✔"

echo
echo "=== 5: zero-residue proof: no leftover sc-work-* session dirs ==="
after=$(mktemp "$work/after.XXXXXX")
find "$tmp_base" -maxdepth 1 -name 'sc-work-*' 2>/dev/null | sort > "$after" || true
diff "$before" "$after" || fail "residual session directories left in $tmp_base"
echo "no residual session directories ✔"

echo
echo "RESULT: keyless disjoint protected merges, identity-gated colliding merges (decryptable by every recipient), secret-registry replay through rebase, unauthorized-clone isolation, zero residue ✔"
