#!/usr/bin/env bash
# Headline proof for P7 (encrypted paths): a path protected for a recipient is
# committed as ciphertext, travels to an unauthorized clone as ciphertext it
# CANNOT read (absent from the checkout), and decrypts only for the recipient.
#
# Self-checking: every claim is an assertion; any failure exits non-zero before
# the success line. Object files are binary (length-prefixed encodings), so all
# content greps use `grep -a` to scan them as text.
set -euo pipefail
cargo build --bin sc >/dev/null 2>&1
SC="$(pwd)/target/debug/sc"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
A="$W/A"; B="$W/B"; KEY="$W/alice.key"

SECRET_PLAINTEXT="TOP_SECRET_db_password_hunter2"
PUBLIC_MARKER="PUBLIC_README_MARKER_xyz"

fail() { echo "FAIL: $1"; exit 1; }

# --- A: init, mint alice's identity, protect secret/, commit a secret file. ---
mkdir -p "$A"; cd "$A"
"$SC" init >/dev/null
ALICE_PK="$(awk '/public key:/{print $3}' < <("$SC" keygen --out "$KEY"))"
printf '[recipients]\nalice = "%s"\n' "$ALICE_PK" > .sc/recipients.toml

"$SC" protect secret/ --to alice >/dev/null
mkdir -p secret
printf '%s\n' "$SECRET_PLAINTEXT" > secret/db.txt
printf '%s\n' "$PUBLIC_MARKER" > README.md          # an UNPROTECTED control file
"$SC" commit -m "add secret" --author me >/dev/null

# The committed protected blob must be CIPHERTEXT: the plaintext must not appear
# anywhere in the object store.
grep -raq "$SECRET_PLAINTEXT" "$A/.sc/objects" \
  && fail "plaintext of secret/db.txt found in A/.sc/objects (not encrypted!)"
# Positive control: an unprotected file's content IS findable in the objects, so
# the grep above is a real test, not vacuously passing because objects are opaque.
grep -raq "$PUBLIC_MARKER" "$A/.sc/objects" \
  || fail "control marker absent from objects — the ciphertext grep is vacuous"
echo "A: secret/db.txt committed as ciphertext (control file is plaintext-readable) ✔"

# --- B: clone WITHOUT alice's key (P6). Clone materializes HEAD with no
#         identity, so the protected file is skipped on checkout. ---
cd "$W"
"$SC" clone "$A" "$B" >/dev/null

[ -f "$B/secret/db.txt" ] && fail "unauthorized clone wrote the protected file to disk"
# But the ciphertext blob did travel: the clone's object store matches the
# origin's exactly, and none of B's objects expose the plaintext.
diff <(cd "$A" && find .sc/objects -type f | sort) \
     <(cd "$B" && find .sc/objects -type f | sort) \
  || fail "clone object store differs from origin"
grep -raq "$SECRET_PLAINTEXT" "$B/.sc/objects" \
  && fail "plaintext leaked into the unauthorized clone's objects"
echo "B (no key): protected file ABSENT from checkout, ciphertext present in objects ✔"

# An explicit keyless switch re-materializes HEAD and reports the skip, never
# writing ciphertext or plaintext for the protected path.
cd "$B"
SKIP="$("$SC" switch main 2>&1 >/dev/null)"
[ -f "$B/secret/db.txt" ] && fail "keyless switch wrote the protected file"
echo "$SKIP" | grep -q "skipped (no key): secret/db.txt" \
  || fail "keyless switch did not report secret/db.txt as skipped"
echo "B (no key): 'sc switch' reports secret/db.txt skipped, file stays absent ✔"

# --- B: switch WITH alice's identity → the protected file decrypts. ---
"$SC" switch main --identity "$KEY" >/dev/null
[ -f "$B/secret/db.txt" ] || fail "authorized switch did not materialize the protected file"
[ "$(cat "$B/secret/db.txt")" = "$SECRET_PLAINTEXT" ] \
  || fail "decrypted content does not match the original plaintext"
echo "B (alice's key): secret/db.txt decrypts to the original plaintext ✔"

echo "RESULT: protected path committed as ciphertext, unreadable in an unauthorized clone, decrypts only for the recipient ✔"
