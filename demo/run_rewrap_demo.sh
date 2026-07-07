#!/usr/bin/env bash
# P17 demo: bulk re-wrap + multi-key escrow. Proves that one `sc rewrap`
# (1) re-seals every pre-escrow secret to the new escrow list,
# (2) strips a revoked recipient's re-attached wraps after a pre-revoke
#     merge (the ADR-0026 R1 boundary, closed), and
# (3) is one undoable operation. Self-checking: every claim is an
# assertion; any failure exits non-zero before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

# Normalize TMPDIR the same way run_protected_merge_demo.sh / run_revoke_demo.sh
# do: strip a trailing slash once so a directory-name glob sees the same base
# on both snapshots.
tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"

fail() { echo "FAIL: $1"; exit 1; }

work=$(mktemp -d "$tmp_base/sc-rewrap-demo.XXXXXX")
trap 'rm -rf "$work"' EXIT

keys="$work/keys"
mkdir -p "$keys"
repo="$work/repo"
mkdir -p "$repo"

# Keyless by construction: point SC_IDENTITY at a path that can never exist,
# so every command below is keyless unless it passes an explicit --identity.
export SC_IDENTITY="$work/no-such-identity"

# Identities live OUTSIDE the repo working tree (P5 scanner flags key material).
alice_pk=$("$SC" keygen --out "$keys/alice" | grep 'public key' | awk '{print $3}')
bob_out="$("$SC" keygen --out "$keys/bob")"
bob_pk=$(echo "$bob_out" | grep 'public key' | awk '{print $3}')
bob_id=$(echo "$bob_out" | grep 'recipient id' | awk '{print $3}')
escrow_out="$("$SC" keygen --out "$keys/escrow")"
escrow_pk=$(echo "$escrow_out" | grep 'public key' | awk '{print $3}')
escrow_id=$(echo "$escrow_out" | grep 'recipient id' | awk '{print $3}')

cd "$repo"
"$SC" init >/dev/null
printf '[recipients]\nalice = "%s"\nbob = "%s"\nescrow = "%s"\n' \
  "$alice_pk" "$bob_pk" "$escrow_pk" > .sc/recipients.toml

# 1. A pre-escrow secret, sealed to alice only.
"$SC" secret add db-pass --to alice --value hunter2 >/dev/null
"$SC" secret list --json | grep -q '"name":"db-pass","recipients":1' \
  || fail "db-pass must start with exactly 1 recipient (alice)"

# 2. Escrow: add a break-glass recipient key and confirm it's recorded.
"$SC" escrow add escrow >/dev/null
"$SC" escrow show | grep -q "$escrow_id" || fail "escrow key not listed by 'sc escrow show'"

# 3. Protect a prefix for alice, commit a file, grant bob, fork a branch while
#    bob is still granted, revoke bob on main, merge -- reproducing the
#    ADR-0026 R1 re-attachment (bob's wrap comes BACK at the merged tip).
"$SC" protect secret/ --to alice >/dev/null
mkdir -p secret && echo "hunter2" > secret/db.txt
"$SC" commit -m "add secret" --author demo >/dev/null
"$SC" grant secret/ --to bob --identity "$keys/alice" >/dev/null
"$SC" protect --list | grep -q "granted" || fail "bob not granted"

"$SC" branch pre-revoke >/dev/null
"$SC" switch pre-revoke >/dev/null
echo "feature" > readme.txt
"$SC" commit -m "feature work" --author demo >/dev/null
"$SC" switch main >/dev/null

"$SC" revoke secret/ --recipient-id "$bob_id" >/dev/null
"$SC" merge pre-revoke --author demo >/dev/null
"$SC" protect --list --json | grep -A2 "\"$bob_id\"" | grep -q '"state": "revoked"' \
  || fail "merge must resurrect bob's wrap via rule union (P16 boundary holds)"

# Behavioral confirmation of the R1 re-attachment, pre-rewrap: bob's identity
# still decrypts the merged tip's protected file (his wrap is back, even
# though he's tombstoned in the rules).
"$SC" switch main --identity "$keys/bob" 2>"$work/pre-rewrap-switch.err" >/dev/null \
  || fail "bob's pre-rewrap switch must succeed"
grep -q "skipped (no key)" "$work/pre-rewrap-switch.err" \
  && fail "bob must still decrypt secret/db.txt before rewrap (R1 re-attachment)"
[ "$(cat secret/db.txt)" = "hunter2" ] \
  || fail "bob's pre-rewrap checkout must show decrypted content"
"$SC" switch main --identity "$keys/alice" >/dev/null

# 4. THE SWEEP: one `sc rewrap` re-seals the pre-escrow secret to alice+escrow
#    AND strips bob's re-attached wrap from the protected blob, in one commit.
rewrap_out=$("$SC" rewrap --identity "$keys/alice" 2>"$work/rewrap.err")
echo "$rewrap_out" | grep -q "rewrapped 1 secret(s)" \
  || fail "rewrap must report exactly 1 secret rewrapped (db-pass), got: $rewrap_out"
echo "$rewrap_out" | grep -Eq "rewrapped 1 secret\(s\), [1-9][0-9]* protected blob" \
  || fail "rewrap must report at least 1 protected blob rewrapped, got: $rewrap_out"
"$SC" secret list --json | grep -q '"name":"db-pass","recipients":2' \
  || fail "db-pass must now show 2 recipients (alice + escrow)"

# 5. ONE UNDO REVERTS THE WHOLE SWEEP. This check must run with NO other
#    oplog-recording command in between: `sc switch` is itself an oplog
#    operation (see run_switch/oplog::record in crates/cli/src/main.rs and
#    crates/repo/src/repo.rs), so if a switch ran here first, `sc undo`
#    would undo that switch instead of the rewrap. Verified BEFORE the R1
#    strip check below, which does need a switch.
"$SC" undo >/dev/null
"$SC" secret list --json | grep -q '"name":"db-pass","recipients":1' \
  || fail "undo must restore db-pass to its pre-rewrap 1 recipient"
# `sc undo` again = redo (documented in CLAUDE.md): back to the fully
# rewrapped tip, so the R1 strip check below runs against the real
# post-rewrap state.
"$SC" undo >/dev/null
"$SC" secret list --json | grep -q '"name":"db-pass","recipients":2' \
  || fail "second undo (= redo) must restore db-pass to 2 recipients"

# 6. THE R1 STRIP: bob's identity, which decrypted this same path a moment
#    ago (step 3's precondition), must now fail to decrypt the post-rewrap
#    tip -- the user-visible proof that his re-attached wrap is gone, not
#    just his standing in the rules (already "revoked" before rewrap ran).
"$SC" switch main --identity "$keys/bob" 2>"$work/post-rewrap-switch.err" >/dev/null \
  || fail "switch itself must still succeed even though a path is skipped"
grep -q "skipped (no key): secret/db.txt" "$work/post-rewrap-switch.err" \
  || fail "bob must be skipped (no key) for secret/db.txt after rewrap strips his wrap"
"$SC" switch main --identity "$keys/alice" >/dev/null
[ "$(cat secret/db.txt)" = "hunter2" ] \
  || fail "alice must still decrypt secret/db.txt after rewrap"

echo "RESULT: bulk rewrap proven -- escrow sweep re-sealed the pre-escrow secret,"
echo "one undo/redo pair flipped the whole sweep atomically (2 -> 1 -> 2"
echo "recipients), and on that same rewrapped tip the R1 re-attached wrap was"
echo "stripped (bob's decrypt flipped success -> skipped)."
