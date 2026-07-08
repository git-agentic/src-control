#!/usr/bin/env bash
# P22 proof: signed commits & provenance. Alice signs two commits and trusts
# green; the signatures ride the wire on a plain `sc clone` (zero wire
# changes per ADR-0032); a REWRITE ATTACK in the clone — `sc amend` over the
# signed tip — is caught by `sc verify --require`, which names the unsigned
# rewrite while the original repo stays clean; and bob's retroactive
# `sc sign` on an old commit shows untrusted (`?`) until bob joins
# `[signers] trusted`, then flips to `✓`.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

fail() { echo "FAIL: $1"; exit 1; }

W="$(mktemp -d)"
# Identity files live directly under $W, never inside a repo working tree,
# so the P5 secret scanner never sees them at commit time.
trap 'rm -rf "$W"' EXIT

ORIG="$W/orig"
CLONE="$W/clone"
mkdir -p "$ORIG"

echo "=== setup: keygen v2 for alice and bob ==="
alice_out=$("$SC" keygen --out "$W/alice.key")
bob_out=$("$SC" keygen --out "$W/bob.key")
alice_sig=$(echo "$alice_out" | awk '/signing key:/{print $3}')
bob_sig=$(echo "$bob_out" | awk '/signing key:/{print $3}')
[ -n "$alice_sig" ] || fail "alice's signing key missing from keygen output"
[ -n "$bob_sig" ] || fail "bob's signing key missing from keygen output"
echo "alice signing key: $alice_sig"
echo "bob signing key:   $bob_sig"

cd "$ORIG"
"$SC" init >/dev/null
{
  printf '[signing]\n'
  printf 'alice = "%s"\n' "$alice_sig"
  printf 'bob = "%s"\n' "$bob_sig"
  printf '\n[signers]\n'
  printf 'trusted = ["alice"]\n'
} > .sc/recipients.toml
echo "both registered under [signing]; only alice trusted ✔"

echo
echo "=== 1: alice commits --sign twice ==="
printf 'one\n' > delta1.txt
"$SC" commit -m "delta1" --author alice --sign --identity "$W/alice.key"
printf 'two\n' > delta2.txt
"$SC" commit -m "delta2" --author alice --sign --identity "$W/alice.key"
echo "two signed commits landed ✔"

echo
echo "=== 2: sc verify --require is green in the original ==="
"$SC" verify --require | tail -1 | grep -q '0 untrusted, 0 invalid, 0 unsigned' \
  || fail "original repo should verify fully trusted before any tampering"
echo "original: fully trusted ✔"

echo
echo "=== 3: clone — signatures ride the existing pack, zero wire changes ==="
cd "$W"
"$SC" clone "$ORIG" "$CLONE" >/dev/null
cd "$CLONE"
# recipients.toml is local repo config, not part of the committed tree —
# the clone needs its own copy to know who to trust.
cp "$ORIG/.sc/recipients.toml" .sc/recipients.toml
"$SC" verify --require | tail -1 | grep -q '0 untrusted, 0 invalid, 0 unsigned' \
  || fail "clone should verify fully trusted — signatures must have traveled with the pack"
echo "clone: signatures traveled, fully trusted ✔"

echo
echo "=== 4: REWRITE ATTACK — sc amend over the signed tip in the clone ==="
pre_attack_tip=$("$SC" log | head -1 | awk '{print $1}')
"$SC" amend -m "innocent-looking" --author attacker >/dev/null
post_attack_tip=$("$SC" log | head -1 | awk '{print $1}')
[ "$pre_attack_tip" != "$post_attack_tip" ] || fail "amend did not produce a new snapshot id"

set +e
verify_out=$("$SC" verify --require 2>&1)
verify_rc=$?
set -e
[ "$verify_rc" -eq 1 ] || fail "verify --require must exit 1 after the rewrite, got $verify_rc"
echo "$verify_out" | grep -q "^${post_attack_tip} unsigned$" \
  || fail "verify must name the rewritten tip ($post_attack_tip) as unsigned; got: $verify_out"
echo "$verify_out" | grep -q '0 untrusted, 0 invalid, 1 unsigned' \
  || fail "verify summary should report exactly one unsigned commit (the rewrite), got: $verify_out"
echo "clone: verify --require exits 1, naming the unsigned rewrite ✔"

echo
echo "=== 5: the ORIGINAL repo is untouched — still verifies clean ==="
cd "$ORIG"
"$SC" verify --require | tail -1 | grep -q '0 untrusted, 0 invalid, 0 unsigned' \
  || fail "the original repo must stay clean — a clone's rewrite cannot reach it"
echo "original: still fully trusted after the clone's rewrite ✔"

echo
echo "=== 6: bob retroactively signs a commit — untrusted until bob joins [signers] ==="
printf 'three\n' > delta3.txt
"$SC" commit -m "delta3" --author alice >/dev/null
"$SC" sign main --identity "$W/bob.key" >/dev/null
log_out=$("$SC" log)
top_two=$(echo "$log_out" | head -2)
echo "$top_two" | grep -q ' ?$' || fail "bob's signature should render untrusted ('?') before bob is trusted: $top_two"
echo "$top_two" | grep -q '✓' && fail "no commit should show trusted (✓) yet: $top_two"
echo "delta3 signed by bob, shown untrusted (?) ✔"

echo
echo "=== 7: bob joins [signers] trusted — the same commit flips to ✓ ==="
{
  printf '[signing]\n'
  printf 'alice = "%s"\n' "$alice_sig"
  printf 'bob = "%s"\n' "$bob_sig"
  printf '\n[signers]\n'
  printf 'trusted = ["alice", "bob"]\n'
} > .sc/recipients.toml
log_out=$("$SC" log)
top_two=$(echo "$log_out" | head -2)
echo "$top_two" | grep -q 'signed: bob ✓' || fail "delta3 should now show trusted: bob: $top_two"
echo "bob trusted — delta3 now shows signed: bob ✓ ✔"

echo
echo "RESULT: alice's history verifies fully trusted, signatures ride a plain clone with"
echo "zero wire changes, a clone-side rewrite is caught by sc verify --require while the"
echo "original stays clean, and bob's retroactive signature moves untrusted -> trusted"
echo "the moment bob joins [signers] ✔"
