#!/usr/bin/env bash
# P30 proof: sealed agent-session transcripts. A transcript body is ALWAYS
# sealed before it enters the CAS (`scl_crypto::seal`, fresh DEK, TAG_SECRET
# shape) and optionally signed; it rides the existing pack with zero wire
# changes (a plain `sc clone` carries it); a keyless clone gets ciphertext
# only (the positive control) while the recipient's identity decrypts the
# EXACT body bytes; `sc log` renders a presence marker without decrypting;
# and gc prunes a transcript whose only snapshot became unreachable (branch
# deleted), rooting it BEFORE the shared signature index so a live
# transcript's own signature survives (ADR-0038).
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

fail() { echo "FAIL: $1"; exit 1; }

WORK="$(mktemp -d)"
# Identity files live directly under $WORK, never inside a repo working
# tree, so the P5 secret scanner never sees them at commit time.
KEYS="$(mktemp -d)"
trap 'rm -rf "$WORK" "$KEYS"' EXIT

ORIGIN="$WORK/origin"
DST="$WORK/dst"
mkdir -p "$ORIGIN"

echo "=== setup: keygen, init, recipients ==="
key_out=$("$SC" keygen --out "$KEYS/id")
PUB=$(echo "$key_out" | awk '/public key:/{print $3}')
[ -n "$PUB" ] || fail "keygen did not print an encryption public key"
# A SECOND, unrelated identity — the keyless positive control below uses this
# (not a missing file) so the test proves the seal gates on recipient
# identity, not merely on "some file happened to be absent".
"$SC" keygen --out "$KEYS/wrong" >/dev/null

cd "$ORIGIN"
"$SC" init >/dev/null
printf '[recipients]\nme = "%s"\n' "$PUB" > .sc/recipients.toml
echo "v1" > app.txt
"$SC" commit -m "first commit" --author me >/dev/null
echo "identity + repo + recipient set up ✔"

echo
echo "=== 1: attach a signed, sealed transcript to main's tip ==="
BODY="$WORK/session.log"
printf 'turn 1: user asked to refactor foo()\nturn 2: agent edited foo.rs\nturn 3: tests green\n' > "$BODY"
attach_out=$("$SC" transcript attach main "$BODY" --agent claude --sign --identity "$KEYS/id")
echo "$attach_out" | grep -q "^attached transcript" || fail "attach did not print a transcript id: $attach_out"
echo "$attach_out"

list_json=$("$SC" transcript list main --json)
TID=$(echo "$list_json" | grep -o '"transcript":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$TID" ] || fail "could not extract transcript id from list --json: $list_json"
echo "$list_json" | grep -q '"agent":"claude"' || fail "list --json missing agent=claude: $list_json"

# The plaintext body must never touch the working tree — attach is index +
# CAS only, no checkout side effect.
[ ! -e "$ORIGIN/session.log" ] || fail "transcript body must not be materialized into the working tree"

# Sanity: right after attach the object is loose on disk (sharded objects/<aa>/<rest>).
OBJ_PATH="$ORIGIN/.sc/objects/${TID:0:2}/${TID:2}"
[ -f "$OBJ_PATH" ] || fail "expected loose transcript object at $OBJ_PATH"
echo "transcript $TID attached, signed, never materialized to disk ✔"

echo
echo "=== 2: clone — the transcript rides the pack, zero wire changes ==="
cd "$WORK"
"$SC" clone "$ORIGIN" "$DST" >/dev/null
cd "$DST"
dst_list=$("$SC" transcript list main --json)
echo "$dst_list" | grep -q "\"transcript\":\"$TID\"" \
  || fail "clone's transcript list is missing $TID — it did not ride the pack: $dst_list"
[ -f ".sc/objects/${TID:0:2}/${TID:2}" ] \
  || fail "clone has no on-disk trace of transcript object $TID"
echo "clone: transcript index + object traveled on a plain sc clone ✔"

echo
echo "=== 3: keyless positive control — ciphertext only without the RIGHT identity ==="
set +e
show_out=$("$SC" transcript show main --identity "$KEYS/wrong" 2>&1)
show_rc=$?
set -e
[ "$show_rc" -ne 0 ] || fail "sc transcript show must fail with the wrong identity, got exit 0: $show_out"
echo "$show_out" | grep -q "turn 1: user asked" && fail "plaintext leaked with the wrong identity: $show_out"
echo "wrong-identity show fails closed, no plaintext leaked (proves the seal gates on recipient) ✔"

show_out=$("$SC" transcript show main --identity "$KEYS/id")
echo "$show_out" | grep -q "turn 1: user asked to refactor foo()" || fail "identity-holder show missing turn 1: $show_out"
echo "$show_out" | grep -q "turn 3: tests green" || fail "identity-holder show missing turn 3: $show_out"
# Byte-exact: diff the decrypted body section against the original file.
decrypted_body=$(echo "$show_out" | tail -n +2)
diff <(printf '%s\n' "$decrypted_body") "$BODY" >/dev/null \
  || fail "decrypted body is not byte-identical to the original transcript file"
echo "sc transcript show --identity decrypts the EXACT body bytes ✔"

echo
echo "=== 4: sc log shows the transcript presence marker ==="
log_out=$("$SC" log)
echo "$log_out" | grep -q 'transcript: 1' || fail "sc log missing the transcript marker: $log_out"
echo "$log_out" | grep -q 'transcript: 1 ✓' || fail "sc log marker should show signed (✓): $log_out"
echo "sc log renders the transcript marker without decrypting ✔"

echo
echo "=== 5: gc prunes a transcript whose only snapshot became unreachable ==="
cd "$ORIGIN"
"$SC" branch throwaway
"$SC" switch throwaway >/dev/null
echo "gone" > gone.txt
"$SC" commit -m "throwaway commit" --author me >/dev/null
"$SC" transcript attach throwaway "$BODY" --agent claude >/dev/null
tid2_json=$("$SC" transcript list throwaway --json)
TID2=$(echo "$tid2_json" | grep -o '"transcript":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$TID2" ] || fail "could not extract throwaway's transcript id: $tid2_json"
OBJ2_PATH="$ORIGIN/.sc/objects/${TID2:0:2}/${TID2:2}"
[ -f "$OBJ2_PATH" ] || fail "expected loose transcript object at $OBJ2_PATH before gc"

"$SC" switch main >/dev/null
rm -f .sc/refs/heads/throwaway
# `sc gc` also treats oplog-referenced snapshot ids as reachability roots
# (undo/redo needs them), trimming records past the grace window before
# computing roots — always keeping the single newest record regardless of
# age. Sleep past a 1s grace window so the throwaway commit's oplog records
# actually age out and stop rooting its transcript, instead of racing the
# same-second timestamps a --prune-expire 0s call would leave untrimmed.
sleep 2
"$SC" gc --prune-expire 1s >/dev/null

[ ! -f "$OBJ2_PATH" ] || fail "gc should have pruned the unreachable transcript object, still on disk at $OBJ2_PATH"
grep -q "$TID2" .sc/transcripts 2>/dev/null && fail "gc should have dropped $TID2 from .sc/transcripts index"
echo "gc pruned the deleted branch's transcript object + index entry ✔"

# Regression: the still-reachable transcript from step 1 survives the same
# gc — reachable objects are repacked, not kept loose, so check via the
# index and a successful decrypt rather than the (now-packed) loose path.
survivor_list=$("$SC" transcript list main --json)
echo "$survivor_list" | grep -q "\"transcript\":\"$TID\"" || fail "surviving transcript missing from list after gc"
"$SC" transcript show main --identity "$KEYS/id" | grep -q "turn 1: user asked to refactor foo()" \
  || fail "surviving transcript no longer decrypts after gc"
echo "gc kept the still-reachable transcript intact (repacked, still decryptable) ✔"

echo
echo "=== 6: zero residue ==="
[ -d .sc/tmp ] && [ -n "$(ls -A .sc/tmp 2>/dev/null)" ] && fail "origin's .sc/tmp is not empty"
[ -d "$DST/.sc/tmp" ] && [ -n "$(ls -A "$DST/.sc/tmp" 2>/dev/null)" ] && fail "clone's .sc/tmp is not empty"
[ ! -e .sc/MERGE_HEAD ] && [ ! -e .sc/PICK_HEAD ] && [ ! -e .sc/REBASE_STATE ] \
  || fail "no history-editing op ran in this demo; no in-progress state should exist"
echo "zero .sc/tmp residue, no in-progress state ✔"

echo
echo "RESULT: a sealed session transcript attaches to a commit, signs, rides a plain"
echo "sc clone with zero wire changes, stays ciphertext-only without the recipient's"
echo "identity while decrypting byte-exact with it, shows a non-decrypting sc log"
echo "marker, and is pruned by gc the moment its only snapshot goes unreachable — all"
echo "while the still-reachable transcript from step 1 survives the same gc ✔"
