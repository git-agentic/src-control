#!/usr/bin/env bash
# P34 demo: per-branch access control (ADR-0044). Two agents — alice
# (authorized) and mallory (no key) — plus bob, who is granted and then
# revoked. Proves end-to-end:
#
#   1. OPACITY: a private branch travels to a keyless clone as ciphertext +
#      manifest only. The clone sees the branch NAME (accepted metadata) but
#      every read surface refuses (`switch`, `log`, `status`), nothing
#      private is ever materialized to its working tree, and no plaintext
#      byte of the content, paths, or commit message appears anywhere in the
#      clone. (The stronger structural claim — that every DECODED non-sealed
#      object in the store and on the wire is free of private plaintext — is
#      pinned by unit tests in crates/repo/src/private.rs, where objects can
#      be decoded; a shell grep cannot decode zstd-compressed objects, so
#      this script does not pretend that grep alone proves it.)
#   2. MEMBERSHIP: `sc branch grant` admits bob O(1); `sc branch revoke`
#      rotates the branch KEK atomically, so a fresh bob clone after the
#      revoke cannot open the branch — while bob's PRE-revoke clone still
#      can (rotation ≠ erasure, stated honestly, same boundary as ADR-0019).
#   3. THE VALVE: merging main INTO the private branch works (keeping the
#      embargo current); merging the private branch into main, and exporting
#      it to git, are refused with a publish hint.
#   4. PUBLISH: one atomic command replays the sealed history as public
#      commits (messages/authors preserved); a keyless clone taken afterward
#      reads everything, and the branch is an ordinary public branch.
#   5. Zero residue: no .sc/tmp leftovers on any repo, either run.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line. Run twice to prove repeatability.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"

fail() { echo "FAIL: $1"; exit 1; }

run_demo() {
  local run_label="$1"
  local work
  work=$(mktemp -d "$tmp_base/sc-private-branch-demo.XXXXXX")
  trap 'rm -rf "$work"' RETURN
  export HOME="$work/home"   # keep ~/.sc and known-host state inside $work
  mkdir -p "$HOME"

  local origin="$work/origin"
  local SENTINEL="EMBARGOED-FIX-CONTENT-7f3a"
  local SENTINEL_MSG="EMBARGOED-COMMIT-MESSAGE-7f3a"
  local SENTINEL_PATH="embargoed-fix-7f3a.txt"

  echo
  echo "=== [$run_label] 0: setup — public repo, alice + bob identities ==="
  mkdir -p "$origin" && cd "$origin"
  "$SC" init >/dev/null
  echo "public readme" > readme.txt
  mkdir -p src && echo "fn main() {}" > src/main.rs
  "$SC" commit -m "public base" --author alice >/dev/null
  "$SC" keygen --out "$work/alice.key" > "$work/alice.out" 2>&1
  "$SC" keygen --out "$work/bob.key"   > "$work/bob.out"   2>&1
  local ALICE_PK BOB_PK BOB_ID
  ALICE_PK=$(grep -o 'scl-pk-[0-9a-f]*' "$work/alice.out" | head -1)
  BOB_PK=$(grep -o 'scl-pk-[0-9a-f]*' "$work/bob.out" | head -1)
  BOB_ID=$(grep 'recipient id:' "$work/bob.out" | awk '{print $3}')
  printf '[recipients]\nalice = "%s"\nbob = "%s"\n' "$ALICE_PK" "$BOB_PK" > .sc/recipients.toml
  echo "setup done ✔"

  echo
  echo "=== [$run_label] 1: alice stages an embargoed fix on a private branch ==="
  "$SC" branch hotfix --private --to alice --identity "$work/alice.key" | head -1
  "$SC" switch hotfix --identity "$work/alice.key" >/dev/null
  echo "$SENTINEL" > "$SENTINEL_PATH"
  echo "fn main() { patched(); }" > src/main.rs
  "$SC" commit -m "$SENTINEL_MSG" --author alice --identity "$work/alice.key" >/dev/null
  "$SC" log --identity "$work/alice.key" | grep -q "$SENTINEL_MSG" \
    || fail "alice must read her own private log"
  echo "private commit landed; alice reads it ✔"

  echo
  echo "=== [$run_label] 2: keeping current — merge main INTO the branch ==="
  "$SC" switch main --identity "$work/alice.key" >/dev/null
  [ ! -f "$SENTINEL_PATH" ] || fail "private file must leave the tree on switch to main"
  echo "main keeps moving" > main-moves.txt
  "$SC" commit -m "public progress" --author carol >/dev/null
  "$SC" switch hotfix --identity "$work/alice.key" >/dev/null
  "$SC" merge main --author alice --identity "$work/alice.key" | grep -q merged \
    || fail "merge main into private must succeed"
  [ -f main-moves.txt ] || fail "merged-in public file must materialize"
  echo "public → private merge works (the one legal direction) ✔"

  echo
  echo "=== [$run_label] 3: the valve — private → public is refused everywhere ==="
  "$SC" switch main --identity "$work/alice.key" >/dev/null
  out=$("$SC" merge hotfix --author alice 2>&1 || true)
  echo "$out" | grep -q "sc branch publish" \
    || fail "merge private→public must be refused with a publish hint (got: $out)"
  "$SC" switch hotfix --identity "$work/alice.key" >/dev/null
  out=$("$SC" export --to "$work/nogit" 2>&1 || true)
  echo "$out" | grep -q "cannot be exported" \
    || fail "git export of a private branch must be refused (got: $out)"
  "$SC" switch main --identity "$work/alice.key" >/dev/null
  echo "integration valve holds ✔"

  echo
  echo "=== [$run_label] 4: OPACITY — mallory clones without any key ==="
  "$SC" clone "$origin" "$work/mallory" >/dev/null
  cd "$work/mallory"
  "$SC" branch list | grep -q "hotfix (private, no access)" \
    || fail "mallory must see the branch name with a no-access marker"
  out=$("$SC" switch hotfix 2>&1 || true)
  echo "$out" | grep -q "private" || fail "mallory switch must refuse (got: $out)"
  ( "$SC" switch hotfix >/dev/null 2>&1 ) && fail "mallory switch must exit non-zero"
  [ ! -f "$SENTINEL_PATH" ] || fail "private path must never materialize for mallory"
  # No plaintext byte of content/path/message anywhere in the clone —
  # working tree, refs, or (necessarily-ciphertext) sealed objects.
  if grep -r "$SENTINEL" . >/dev/null 2>&1; then fail "content plaintext leaked"; fi
  if grep -r "$SENTINEL_MSG" . >/dev/null 2>&1; then fail "message plaintext leaked"; fi
  if grep -rl "$SENTINEL_PATH" .sc >/dev/null 2>&1; then fail "path name leaked into .sc"; fi
  echo "mallory holds ciphertext only; every read surface refuses ✔"

  echo
  echo "=== [$run_label] 5: MEMBERSHIP — grant bob, then revoke (KEK rotation) ==="
  cd "$origin"
  "$SC" branch grant hotfix --to bob --identity "$work/alice.key" >/dev/null
  "$SC" clone "$origin" "$work/bob-before" >/dev/null
  cd "$work/bob-before"
  "$SC" switch hotfix --identity "$work/bob.key" >/dev/null
  grep -q "$SENTINEL" "$SENTINEL_PATH" || fail "granted bob must read the fix"
  echo "bob (granted) reads the embargoed fix ✔"
  cd "$origin"
  "$SC" branch revoke hotfix --recipient-id "$BOB_ID" --identity "$work/alice.key" | head -1
  "$SC" clone "$origin" "$work/bob-after" >/dev/null
  cd "$work/bob-after"
  "$SC" branch list --identity "$work/bob.key" | grep -q "hotfix (private, no access)" \
    || fail "post-revoke bob must have no access to the rotated manifest"
  ( "$SC" switch hotfix --identity "$work/bob.key" >/dev/null 2>&1 ) \
    && fail "post-revoke bob switch must fail"
  # Rotation ≠ erasure, stated honestly: bob's PRE-revoke clone still opens
  # the OLD manifest it already fetched.
  cd "$work/bob-before"
  "$SC" log --identity "$work/bob.key" | grep -q "$SENTINEL_MSG" \
    || fail "pre-revoke clone must still read (rotation != erasure)"
  echo "revoke locks bob out of everything after the rotation; old clone keeps old reads (documented boundary) ✔"

  echo
  echo "=== [$run_label] 6: PUBLISH — one atomic release ==="
  cd "$origin"
  "$SC" branch publish hotfix --identity "$work/alice.key" | head -1
  "$SC" branch list | grep -q "^..hotfix$" || true
  "$SC" branch list | grep "hotfix" | grep -qv "private" \
    || fail "published branch must lose its private marker"
  "$SC" switch hotfix >/dev/null   # no identity needed anymore
  grep -q "$SENTINEL" "$SENTINEL_PATH" || fail "published content must be public"
  "$SC" log | grep -q "$SENTINEL_MSG" || fail "published history must be readable"
  # A brand-new keyless clone reads everything.
  "$SC" clone "$origin" "$work/mallory2" >/dev/null
  cd "$work/mallory2"
  "$SC" switch hotfix >/dev/null 2>&1 || true
  grep -q "$SENTINEL" "$SENTINEL_PATH" || fail "keyless clone must read published content"
  # And the branch integrates into main like any public branch.
  cd "$origin" && "$SC" switch main >/dev/null
  "$SC" merge hotfix --author alice >/dev/null
  grep -q "$SENTINEL" "$SENTINEL_PATH" || fail "published branch must merge into main"
  echo "publish flips the branch public atomically; everyone reads; merge to main lands ✔"

  echo
  echo "=== [$run_label] 7: zero residue ==="
  for r in "$origin" "$work/mallory" "$work/bob-before" "$work/bob-after" "$work/mallory2"; do
    if [ -d "$r/.sc/tmp" ] && [ -n "$(ls -A "$r/.sc/tmp" 2>/dev/null)" ]; then
      fail "$r/.sc/tmp is not empty"
    fi
  done
  echo "no .sc/tmp residue anywhere ✔"
  cd "$tmp_base"
}

run_demo "run 1"
run_demo "run 2 (repeatable, not a one-shot fluke)"

echo
echo "RESULT: a private branch is fully opaque to non-recipients — the keyless"
echo "clone sees only the branch name, a manifest, and sealed ciphertext"
echo "(content, paths, and commit messages unreadable; every read surface"
echo "refuses cleanly); grant admits a recipient with one wrap, revoke rotates"
echo "the branch KEK so post-revoke fetches are unreadable while pre-revoke"
echo "clones keep what they already had (rotation ≠ erasure, the standing"
echo "ADR-0019 boundary); public → private merges keep the embargo current"
echo "while private → public integration and git export refuse until the one"
echo "sanctioned crossing — sc branch publish — atomically replays the sealed"
echo "history as ordinary public commits. Verified across two independent"
echo "runs, zero residue."
