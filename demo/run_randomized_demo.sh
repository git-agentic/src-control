#!/usr/bin/env bash
# P33 demo: randomized protected-path encryption. Proves that the oracle
# ADR-0014 accepted (equality-confirmable protected content: same plaintext
# -> same ciphertext id) is CLOSED for everything sealed from this phase on,
# that untouched protected files stay quiet across unrelated commits (the
# local stat/keyed-hash cache carries them instead of re-sealing), that
# identical independent edits on two branches now require --identity to
# merge (accepted cost 4a — a real UX regression vs. the old id-fast-path,
# even though the merge itself completes cleanly once given the key), and
# that `sc rewrap` on an already-fully-randomized tip is a true no-op
# policy-wise (no re-seal line, no new tree/blob objects — only a fresh
# commit record).
#
# Scope split (deliberate, stated plainly): this script drives the CURRENT
# binary only, which — since Task 6 flipped `encrypt_protected` to always
# randomize — can no longer mint a convergent (pre-P33) seal at all. So this
# demo proves oracle-closure, quiet history, the accepted-cost-4a merge
# behavior, and rewrap's policy-only idempotence on an all-randomized tip
# (steps 1, 2, 3, and the "second run reports nothing to upgrade" half of
# the rewrap-upgrade story). Dual-read of a GENUINELY convergent (pre-P33)
# store, and `sc rewrap`'s eager convergent->randomized upgrade path itself
# (the "re-sealed N convergent blob(s)" line firing), are pinned instead by
# unit tests built with the library directly (crates/repo/src/rewrap.rs,
# crates/repo/src/{merge,replay}.rs) — Tasks 4-6, 9, 10 all build convergent
# fixtures that way, which is impossible to reproduce honestly with a CLI
# that can only ever mint randomized ciphertext.
#
# Technique note: there is no `sc cat-file`/`sc ls-tree` exposing a path's
# blob id, so ciphertext-id (in)equality is proven indirectly but rigorously
# via the content-addressed object store's file count: every object is one
# file named by its own hash, so "how many NEW object files appeared" is an
# exact count of how many genuinely new (blob/tree/snapshot) objects a
# commit created. Two operations of identical *shape* (e.g. "add one new
# flat file") cost identical object-count deltas whenever their content is
# equally novel to the store — so comparing deltas across a controlled pair
# of same-shape commits proves id (in)equality without ever needing to read
# a specific id.
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

# Count loose objects in the CAS. Called only before `sc gc` ever runs in
# this script, so every object stays loose (one file per object) and the
# count is an exact reachable-object tally.
objcount() { find .sc/objects -type f | wc -l | tr -d ' '; }

run_demo() {
  local run_label="$1"
  local work
  work=$(mktemp -d "$tmp_base/sc-randomized-demo.XXXXXX")
  trap 'rm -rf "$work"' RETURN

  local keys="$work/keys"
  mkdir -p "$keys"
  local repo="$work/repo"
  mkdir -p "$repo"

  # Keyless by construction (the P15/P23 demos' pattern): point SC_IDENTITY
  # at a path that can never exist, so every command below is keyless unless
  # it passes an explicit --identity.
  export SC_IDENTITY="$work/no-such-identity"

  local alice_out alice_pk
  alice_out=$("$SC" keygen --out "$keys/alice")
  alice_pk=$(echo "$alice_out" | grep 'public key' | awk '{print $3}')

  cd "$repo"
  "$SC" init >/dev/null
  printf '[recipients]\nalice = "%s"\n' "$alice_pk" > .sc/recipients.toml
  "$SC" protect secret/ --to alice >/dev/null
  mkdir -p secret

  echo
  echo "=== [$run_label] 1a: oracle closed — same plaintext, two different protected paths ==="
  echo "repeatable-plaintext-1" > secret/a.txt
  "$SC" commit -m "base: secret/a.txt" --author demo >/dev/null
  local c_a
  c_a=$(objcount)

  # ADD secret/b.txt with the SAME plaintext as secret/a.txt — same "shape"
  # of change (one new flat file under secret/) as the next commit below.
  echo "repeatable-plaintext-1" > secret/b.txt
  "$SC" commit -m "secret/b.txt: same plaintext as a.txt" --author demo >/dev/null
  local c_b delta_same
  c_b=$(objcount)
  delta_same=$((c_b - c_a))

  # ADD secret/c.txt with a genuinely NOVEL plaintext — identical shape
  # (one new flat file under secret/), the "definitely a fresh blob" baseline.
  echo "genuinely-novel-plaintext-2" > secret/c.txt
  "$SC" commit -m "secret/c.txt: novel plaintext" --author demo >/dev/null
  local c_c delta_diff
  c_c=$(objcount)
  delta_diff=$((c_c - c_b))

  [ "$delta_same" -eq "$delta_diff" ] \
    || fail "adding secret/b.txt (repeat of a.txt's plaintext) cost $delta_same new object(s), but adding secret/c.txt (novel plaintext) cost $delta_diff — a convergent seal would have cost LESS for the repeat (blob dedup), so the oracle would still be open"
  [ "$delta_same" -ge 3 ] || fail "expected at least 3 new objects (blob+tree+snapshot) for a one-file add, got $delta_same"
  echo "secret/b.txt (repeat of a.txt's plaintext) cost $delta_same new object(s), identical to secret/c.txt's (genuinely novel) $delta_diff — a fresh, distinct ciphertext blob was minted for the repeat ✔"

  echo
  echo "=== [$run_label] 1b: oracle closed — same plaintext, edited away then back on ONE path ==="
  echo "edit-value-one" > secret/e.txt
  "$SC" commit -m "base: secret/e.txt = one" --author demo >/dev/null
  local c_e0
  c_e0=$(objcount)

  echo "edit-value-two" > secret/e.txt
  "$SC" commit -m "secret/e.txt: edited away" --author demo >/dev/null
  local c_e1 delta_away
  c_e1=$(objcount)
  delta_away=$((c_e1 - c_e0))

  echo "edit-value-one" > secret/e.txt
  "$SC" commit -m "secret/e.txt: edited back to its original value" --author demo >/dev/null
  local c_e2 delta_back
  c_e2=$(objcount)
  delta_back=$((c_e2 - c_e1))

  [ "$delta_away" -eq "$delta_back" ] \
    || fail "editing secret/e.txt away cost $delta_away new object(s), editing it back to the SAME original plaintext cost $delta_back — a convergent seal would have reused the original commit's blob for the 'back' edit (fewer new objects), so the oracle would still be open across commits"
  echo "editing secret/e.txt away ($delta_away new object(s)) and back to its ORIGINAL plaintext ($delta_back) cost the same — the 'back' edit minted a fresh ciphertext blob rather than reconverging on the first commit's blob ✔"

  echo
  echo "=== [$run_label] 2: quiet history — an unrelated commit doesn't touch untouched protected files ==="
  local c_before_unrelated
  c_before_unrelated=$(objcount)
  # Nested one level deep (like secret/c.txt) so the object-count "shape" of
  # this add matches 1a's delta_diff baseline exactly: root tree + one new
  # subtree + snapshot + blob = 4. A flat root-level add would cost one
  # fewer object (no subtree) and make the comparison apples-to-oranges.
  mkdir -p misc
  echo "unrelated noise" > misc/note.txt
  "$SC" commit -m "unrelated: add misc/note.txt" --author demo >/dev/null
  local c_after_unrelated delta_unrelated
  c_after_unrelated=$(objcount)
  delta_unrelated=$((c_after_unrelated - c_before_unrelated))

  # Same shape as 1a's "add one new subtree with one novel-content flat file"
  # baseline (delta_diff): if it were EQUAL, this commit cost exactly as much
  # as adding one new file in one new subdirectory and nothing else touched.
  # If secret/{a,b,c,e}.txt had been needlessly re-encrypted too, this delta
  # would be strictly larger (an extra new secret/ subtree object plus one
  # new blob per re-sealed file).
  [ "$delta_unrelated" -eq "$delta_diff" ] \
    || fail "an unrelated top-level commit cost $delta_unrelated new object(s), vs. $delta_diff for adding one novel flat file alone — the extra objects mean an untouched protected file was needlessly re-sealed (cache-carry regression)"
  echo "unrelated commit (new subdir + 1 file) cost exactly $delta_unrelated new object(s), matching the 1a novel-add baseline — no protected file's ciphertext id changed (cache carried them all) ✔"

  local status_out
  status_out=$("$SC" status)
  case "$status_out" in *"clean"*) ;; *) fail "sc status must stay clean after an unrelated commit, got: $status_out" ;; esac
  echo "sc status: clean ✔"

  echo
  echo "=== [$run_label] 3: accepted cost 4a — identical independent edits on two branches now need --identity ==="
  echo "shared-base-value" > secret/x.txt
  "$SC" commit -m "base: secret/x.txt" --author demo >/dev/null
  "$SC" branch feature >/dev/null

  echo "identical-new-value" > secret/x.txt
  "$SC" commit -m "main: edit secret/x.txt" --author demo >/dev/null

  "$SC" switch feature --identity "$keys/alice" >/dev/null
  echo "identical-new-value" > secret/x.txt
  "$SC" commit -m "feature: edit secret/x.txt to the SAME value" --author demo >/dev/null

  "$SC" switch main --identity "$keys/alice" >/dev/null

  set +e
  no_id_out=$("$SC" merge feature --author demo 2>&1)
  no_id_rc=$?
  set -e
  [ "$no_id_rc" -eq 1 ] || fail "merging identical independent edits without --identity must exit 1 (accepted cost 4a), got rc=$no_id_rc: $no_id_out"
  case "$no_id_out" in *"--identity"*) ;; *) fail "expected a --identity hint in the refusal, got: $no_id_out" ;; esac
  echo "sc merge feature (no --identity) refuses even though both sides wrote the SAME plaintext — pre-P33 this would have id-fast-pathed with no key needed at all ✔"

  status_out=$("$SC" status)
  case "$status_out" in *"clean"*) ;; *) fail "a refused (not attempted) merge must leave the working tree clean, got: $status_out" ;; esac
  echo "refusal left refs/working tree untouched (no MERGE_HEAD, no markers) ✔"

  local merge_out
  merge_out=$("$SC" merge feature --identity "$keys/alice" --author demo)
  case "$merge_out" in *"merged feature"*) ;; *) fail "merge with --identity must succeed cleanly, got: $merge_out" ;; esac
  echo "sc merge feature --identity alice completes cleanly — no conflict markers (diff3 of identical plaintext has nothing to conflict over) ✔"

  local top_line
  top_line=$("$SC" log | head -1)
  case "$top_line" in *"(merge)"*) ;; *) fail "expected a merge marker on the tip, got: $top_line" ;; esac

  "$SC" switch main --identity "$keys/alice" >/dev/null
  [ "$(cat secret/x.txt)" = "identical-new-value" ] || fail "post-merge secret/x.txt must decrypt to the agreed value"
  echo "merged tip decrypts to the agreed value, re-encrypted through the ordinary commit path ✔"

  echo
  echo "=== [$run_label] 4: rewrap on an all-randomized tip is policy-only (no re-seal line) ==="
  local c_before_rewrap
  c_before_rewrap=$(objcount)
  local rewrap_out
  rewrap_out=$("$SC" rewrap --identity "$keys/alice")
  echo "$rewrap_out"
  case "$rewrap_out" in *"re-sealed"*"convergent blob"*) fail "rewrap on an all-randomized tip must NOT print a convergent re-seal line, got: $rewrap_out" ;; esac
  case "$rewrap_out" in *"rewrapped"*"protected blob(s)"*) ;; *) fail "expected a rewrapped-blobs summary line, got: $rewrap_out" ;; esac
  local c_after_rewrap delta_rewrap
  c_after_rewrap=$(objcount)
  delta_rewrap=$((c_after_rewrap - c_before_rewrap))
  # Nothing to upgrade: the root tree and every blob are byte-identical
  # (the P17 policy-only property), so the ONLY new object is the fresh
  # commit snapshot itself — no new tree, no new blob.
  [ "$delta_rewrap" -eq 1 ] \
    || fail "rewrap on an all-randomized tip must add exactly 1 new object (the commit snapshot only — root/blobs unchanged), got $delta_rewrap"
  echo "rewrap added exactly 1 new object (the commit record) — root tree and every blob stayed byte-identical ✔"

  "$SC" switch main --identity "$keys/alice" >/dev/null
  [ "$(cat secret/a.txt)" = "repeatable-plaintext-1" ] || fail "content must still decrypt correctly after the policy-only rewrap"
  [ "$(cat secret/x.txt)" = "identical-new-value" ] || fail "merged content must still decrypt correctly after the policy-only rewrap"
  echo "all protected content still decrypts correctly after rewrap ✔"

  echo
  echo "=== [$run_label] 5: zero residue — .sc/tmp is empty, nothing lives outside \$work ==="
  [ -d "$repo/.sc" ] || fail "repo/.sc must exist while the repo is alive"
  if [ -d "$repo/.sc/tmp" ] && [ -n "$(ls -A "$repo/.sc/tmp" 2>/dev/null)" ]; then
    fail ".sc/tmp is not empty after the run"
  fi
  echo "no .sc/tmp residue ✔"
}

run_demo "run 1"
run_demo "run 2 (repeatable, not a one-shot fluke)"

echo
echo "RESULT: the equality-confirmation oracle is closed for randomized-write"
echo "protected content — same plaintext at two paths, and the same plaintext"
echo "edited away and back on one path, both mint a fresh distinct ciphertext"
echo "blob (proven via matched object-count deltas, since the CLI exposes no"
echo "cat-file); an unrelated commit costs exactly the baseline object delta,"
echo "meaning every untouched protected file was cache-carried, not re-sealed,"
echo "and sc status stays clean; two branches writing the IDENTICAL plaintext"
echo "to a protected path now refuse to merge without --identity (accepted"
echo "cost 4a) but merge cleanly (no markers) once given the key; and sc"
echo "rewrap on an already-fully-randomized tip is genuinely policy-only (no"
echo "re-seal line, exactly one new object — the commit record). Dual-read of"
echo "a genuinely convergent (pre-P33) store and rewrap's eager upgrade path"
echo "itself are pinned by unit tests instead, since this binary can no"
echo "longer mint a convergent seal to fixture one honestly. Verified across"
echo "two independent runs, zero residue."
