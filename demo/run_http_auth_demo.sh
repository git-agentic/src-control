#!/usr/bin/env bash
# P29 sc+http access-control demo: bearer-token auth, per-connection
# read-only enforcement, and the fail-closed non-loopback bind gate — the
# second half of the P28/P29 security horizon, layered on P26's plain
# `sc serve --http` (unauthenticated/unrestricted before this phase).
#
# `sc serve token add --label <name> --scope ro|rw` mints a token in
# `.sc/serve-tokens.toml` and prints the raw value ONCE on stdout (the
# confirmation line goes to stderr, so `$(...)` capture gets exactly the
# raw token, matching `sc keygen`'s pattern). Once ANY token is configured,
# a valid `Authorization: Bearer` is required on every connection, loopback
# included; an `ro`-scope token floors the connection read-only.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

fail() { echo "FAIL: $1"; exit 1; }

W="$(mktemp -d)"
A="$W/A"
A2="$W/A2"
SERVER_PID=""
SERVER2_PID=""

cleanup() {
  for pid in "$SERVER_PID" "$SERVER2_PID"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$W"
}
trap cleanup EXIT

# --- Pick two distinct free ports; probe with `nc -z` first. ---
pick_port() {
  local exclude="$1"
  local candidate
  for candidate in 8741 8742 8743 8901 18741 18742; do
    [ "$candidate" = "$exclude" ] && continue
    if ! nc -z 127.0.0.1 "$candidate" 2>/dev/null; then
      echo "$candidate"
      return 0
    fi
  done
  fail "no free port found among the candidates"
}
PORT="$(pick_port '')"
PORT2="$(pick_port "$PORT")"

wait_for_port() {
  local port="$1" tries=0
  while ! nc -z 127.0.0.1 "$port" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -lt 100 ] || fail "server on port $port never became ready"
    sleep 0.05
  done
}

check_no_tmp_residue() {
  local dir="$1" label="$2"
  [ -d "$dir/.sc/tmp" ] && [ -n "$(ls -A "$dir/.sc/tmp" 2>/dev/null)" ] \
    && fail "$label: .sc/tmp is not empty"
  return 0
}

echo "=== 1: init origin A, one commit, mint an rw and an ro token ==="
mkdir -p "$A"; cd "$A"
"$SC" init >/dev/null
printf 'v1\n' > tracked.txt
"$SC" commit -m "initial" --author origin >/dev/null

# Raw tokens print ONCE on stdout; the confirmation ("store this value now")
# goes to stderr, so command substitution captures exactly the raw value.
RW_TOK="$("$SC" serve token add --label writer --scope rw 2>/dev/null)"
RO_TOK="$("$SC" serve token add --label reader --scope ro 2>/dev/null)"
[ -n "$RW_TOK" ] || fail "rw token add produced no stdout value"
[ -n "$RO_TOK" ] || fail "ro token add produced no stdout value"
echo "A: initial commit; rw token '${RW_TOK:0:8}…', ro token '${RO_TOK:0:8}…' ✔"

TOK_LIST="$("$SC" serve token list)"
echo "$TOK_LIST" | grep -q "writer" || fail "token list missing 'writer'"
echo "$TOK_LIST" | grep -q "reader" || fail "token list missing 'reader'"
echo "A: sc serve token list shows both labels ✔"

echo
echo "=== 2: sc serve --http 127.0.0.1:$PORT (background, tokens configured) ==="
cd "$W"
"$SC" serve --http "127.0.0.1:$PORT" "$A" &
SERVER_PID=$!
wait_for_port "$PORT"
echo "server: listening on 127.0.0.1:$PORT (pid $SERVER_PID), auth mandatory ✔"

URL="sc+http://127.0.0.1:$PORT/repo"

echo
echo "=== 3: no token -> clone rejected (401, auth error) ==="
if SC_HTTP_TOKEN= "$SC" clone "$URL" "$W/c-noauth" 2>"$W/err-noauth.txt"; then
  fail "no-token clone should have been rejected"
fi
grep -qi "authentication" "$W/err-noauth.txt" \
  || fail "expected an authentication error, got: $(cat "$W/err-noauth.txt")"
[ ! -e "$W/c-noauth" ] || fail "rejected clone should not have created a destination"
echo "no-token clone: rejected with an authentication error, no partial clone left behind ✔"

echo
echo "=== 4: ro token -> clone succeeds; ro token -> push rejected read-only ==="
SC_HTTP_TOKEN="$RO_TOK" "$SC" clone "$URL" "$W/c-ro" >/dev/null
[ "$(cat "$W/c-ro/tracked.txt")" = "v1" ] || fail "c-ro: clone content mismatch"
echo "ro token: clone succeeded ✔"

cd "$W/c-ro"
printf 'from ro client\n' > from_ro.txt
"$SC" commit -m "from-ro" --author roclient >/dev/null
if SC_HTTP_TOKEN="$RO_TOK" "$SC" push origin 2>"$W/err-ro-push.txt"; then
  fail "ro-token push should have been rejected"
fi
grep -qi "read-only" "$W/err-ro-push.txt" \
  || fail "expected a read-only error, got: $(cat "$W/err-ro-push.txt")"
echo "ro token: push rejected read-only ✔"

echo
echo "=== 5: rw token -> push lands; a later ro clone sees it ==="
SC_HTTP_TOKEN="$RW_TOK" "$SC" push origin >/dev/null
echo "rw token: push landed ✔"

SC_HTTP_TOKEN="$RO_TOK" "$SC" clone "$URL" "$W/c-verify" >/dev/null
cd "$W/c-verify"
"$SC" log | grep -q "from-ro" || fail "c-verify: pushed commit did not propagate"
echo "ro token: fresh clone sees the rw-pushed commit ✔"

echo
echo "=== 6: zero .sc/tmp residue on origin + every clone after the transfers ==="
check_no_tmp_residue "$A" "origin A"
check_no_tmp_residue "$W/c-ro" "c-ro"
check_no_tmp_residue "$W/c-verify" "c-verify"
echo "origin + clones: zero .sc/tmp residue ✔"

echo
echo "=== 7: stop the token-authed server ==="
kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
! nc -z 127.0.0.1 "$PORT" 2>/dev/null || fail "server still accepting connections after kill"
echo "server: stopped ✔"

echo
echo "=== 8: fail-closed bind — a fresh repo with NO tokens configured ==="
mkdir -p "$A2"; cd "$A2"
"$SC" init >/dev/null
printf 'unrelated\n' > other.txt
"$SC" commit -m "initial" --author origin2 >/dev/null
cd "$W"

if "$SC" serve --http "0.0.0.0:$PORT2" "$A2" 2>"$W/err-bind.txt"; then
  fail "non-loopback bind with no --read-only/--allow-public/tokens should have been refused"
fi
grep -qi "refusing to bind" "$W/err-bind.txt" \
  || fail "expected a 'refusing to bind' error, got: $(cat "$W/err-bind.txt")"
echo "unjustified public bind (0.0.0.0, no tokens): refused ✔"

"$SC" serve --http "0.0.0.0:$PORT2" --allow-public "$A2" &
SERVER2_PID=$!
wait_for_port "$PORT2"
echo "public bind (0.0.0.0, --allow-public): accepted ✔"
kill "$SERVER2_PID"
wait "$SERVER2_PID" 2>/dev/null || true
SERVER2_PID=""
! nc -z 127.0.0.1 "$PORT2" 2>/dev/null || fail "second server still accepting connections after kill"
echo "server: stopped ✔"

check_no_tmp_residue "$A2" "origin A2"

echo
echo "RESULT: sc+http access control — a no-token clone is rejected (401,"
echo "authentication error), an ro-token clone reads but its push is rejected"
echo "read-only, an rw-token push lands and a later ro-token clone sees it,"
echo "an unjustified non-loopback bind is refused while --allow-public opens"
echo "it deliberately, and zero .sc/tmp residue is left anywhere. OK"
