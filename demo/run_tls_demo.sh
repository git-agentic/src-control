#!/usr/bin/env bash
# P32 sc+https demo: TLS-wrapped sc-native HTTP transport. `sc serve --http
# <addr> --tls <path>` auto-mints a self-signed identity into
# `.sc/serve-tls/` (key.pem mode 0600) and banners its SHA-256 SPKI
# fingerprint on startup; `sc serve fingerprint <path>` prints the same
# fingerprint up front, before first serve, so an operator can distribute it
# out of band. `sc clone/push/fetch` on `sc+https://host:port/` URLs verify
# the server's key against a local TOFU pin store (`SC_HTTPS_KNOWN_HOSTS`,
# defaulting to a user-level file): first connect pins and announces loudly,
# later connects are quiet, a swapped server key hard-fails, `SC_HTTPS_STRICT`
# refuses an unknown host outright, and `SC_HTTPS_FINGERPRINT` pre-pins
# without ever persisting. Finally, P32 tightens the P29 non-loopback bind
# gate: a plaintext public bind justified only by configured tokens (the old
# P29 rule) is now refused — a bearer token must not cross the wire in the
# clear — while `--tls` plus a configured token still justifies it.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

fail() { echo "FAIL: $1"; exit 1; }

W=""
SERVER_PID=""
SERVER2_PID=""

cleanup() {
  for pid in "$SERVER_PID" "$SERVER2_PID"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [ -n "$W" ]; then rm -rf "$W"; fi
  return 0
}
trap cleanup EXIT

# --- Pick a free port, excluding any already handed out this run. ---
USED_PORTS=""
pick_port() {
  local candidate
  for candidate in 8761 8762 8763 8764 8765 18761 18762 18763; do
    case " $USED_PORTS " in *" $candidate "*) continue ;; esac
    if ! nc -z 127.0.0.1 "$candidate" 2>/dev/null; then
      USED_PORTS="$USED_PORTS $candidate"
      echo "$candidate"
      return 0
    fi
  done
  fail "no free port found among the candidates"
}

wait_for_port() {
  local port="$1" tries=0
  while ! nc -z 127.0.0.1 "$port" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -lt 100 ] || fail "server on port $port never became ready"
    sleep 0.05
  done
}

# --- Wait for a background server's stdout file to contain a line (the
#     port opening the socket and the process flushing its startup banner
#     are not perfectly synchronized). ---
wait_for_line() {
  local file="$1" pattern="$2" tries=0
  while ! grep -q "$pattern" "$file" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -lt 100 ] || fail "'$pattern' never appeared in $file: $(cat "$file" 2>/dev/null)"
    sleep 0.05
  done
}

# --- File mode, portable across BSD (macOS) and GNU stat. ---
file_mode() {
  stat -f "%Lp" "$1" 2>/dev/null || stat -c "%a" "$1"
}

check_no_tmp_residue() {
  local dir="$1" label="$2"
  [ -d "$dir/.sc/tmp" ] && [ -n "$(ls -A "$dir/.sc/tmp" 2>/dev/null)" ] \
    && fail "$label: .sc/tmp is not empty"
  return 0
}

run_demo() {
  local run_label="$1"
  W="$(mktemp -d)"
  SERVER_PID=""
  SERVER2_PID=""
  local ORIGIN="$W/origin"

  echo "=== [$run_label] 1: init origin, keygen (outside the tree), sign a ~1 MiB blob, mint a token ==="
  mkdir -p "$ORIGIN"; cd "$ORIGIN"
  "$SC" init >/dev/null
  "$SC" keygen --out "$W/alice.id" >/dev/null
  # Deterministic ~1 MiB blob. Repeating text, not high-entropy binary — the
  # P5 commit scanner flags entropy-dense content as a possible secret.
  head -c 1048576 /dev/zero | tr '\0' 'x' > big.bin
  "$SC" commit -m "big" --sign --identity "$W/alice.id" >/dev/null
  # Raw token prints once on stdout; the confirmation goes to stderr, so
  # command substitution captures exactly the raw value.
  TOKEN="$("$SC" serve token add --label demo --scope rw 2>/dev/null)"
  [ -n "$TOKEN" ] || fail "token add produced no stdout value"
  echo "origin: signed commit with a ~1 MiB blob; rw token '${TOKEN:0:8}…' ✔"

  echo
  echo "=== [$run_label] 2: sc serve fingerprint mints the identity before any serve ==="
  FPR="$("$SC" serve fingerprint "$ORIGIN")"
  case "$FPR" in
    sha256:*) ;;
    *) fail "fingerprint must start with sha256:, got: $FPR" ;;
  esac
  [ -f "$ORIGIN/.sc/serve-tls/key.pem" ] || fail "sc serve fingerprint must mint .sc/serve-tls/key.pem"
  KEY_MODE="$(file_mode "$ORIGIN/.sc/serve-tls/key.pem")"
  [ "$KEY_MODE" = "600" ] || fail "key.pem must be mode 600, got: $KEY_MODE"
  echo "fingerprint: $FPR, key.pem minted at mode 600 ✔"

  echo
  echo "=== [$run_label] 3: sc serve --http --tls (background); TLS clone pins on first connect ==="
  cd "$W"
  PORT="$(pick_port)"
  "$SC" serve --http "127.0.0.1:$PORT" --tls "$ORIGIN" \
    >"$W/server1.out" 2>"$W/server1.err" &
  SERVER_PID=$!
  wait_for_port "$PORT"
  wait_for_line "$W/server1.out" "^listening on 127.0.0.1:$PORT\$"
  wait_for_line "$W/server1.out" "tls fingerprint: $FPR"
  echo "server: listening on 127.0.0.1:$PORT (pid $SERVER_PID), banner matches $FPR ✔"

  URL="sc+https://127.0.0.1:$PORT/"
  KH="$W/known_hosts"

  SC_HTTP_TOKEN="$TOKEN" SC_HTTPS_KNOWN_HOSTS="$KH" SC_PACK_CHUNK=4096 \
    "$SC" clone "$URL" "$W/clone" 2>"$W/clone1.err"
  grep -q "pinned" "$W/clone1.err" || fail "first connect must announce a pin: $(cat "$W/clone1.err")"
  grep -qF "$FPR" "$W/clone1.err" || fail "pin announcement must include the fingerprint: $(cat "$W/clone1.err")"
  [ -f "$KH" ] || fail "TOFU pin must have been recorded to SC_HTTPS_KNOWN_HOSTS"
  cmp -s "$ORIGIN/big.bin" "$W/clone/big.bin" || fail "cloned big.bin is not byte-identical to origin"
  (cd "$W/clone" && "$SC" log) | grep -q "signed:" \
    || fail "clone's sc log must show the signed: marker"
  echo "TLS clone: first-connect pin announced with the fingerprint, blob byte-identical, signature marker present ✔"

  echo
  echo "=== [$run_label] 4: second connect is quiet; push + fetch round-trip over TLS ==="
  cd "$W/clone"
  printf 'from clone over tls\n' > new.txt
  "$SC" commit -m "edit" >/dev/null
  SC_HTTP_TOKEN="$TOKEN" SC_HTTPS_KNOWN_HOSTS="$KH" "$SC" push origin 2>"$W/push.err"
  grep -q "pinned" "$W/push.err" && fail "second connect must be quiet, got: $(cat "$W/push.err")"
  echo "push: landed, second connect made no TOFU announcement ✔"

  cd "$W"
  SC_HTTP_TOKEN="$TOKEN" SC_HTTPS_KNOWN_HOSTS="$KH" "$SC" clone "$URL" "$W/clone2" >/dev/null
  [ "$(cat "$W/clone2/new.txt")" = "from clone over tls" ] \
    || fail "clone2 did not see the pushed edit"
  echo "clone2: sees the pushed edit ✔"

  echo
  echo "=== [$run_label] 5: SC_HTTPS_STRICT refuses an unknown host; SC_HTTPS_FINGERPRINT pre-pins without persisting ==="
  KH_FRESH="$W/known_hosts_fresh"
  if SC_HTTPS_STRICT=1 SC_HTTP_TOKEN="$TOKEN" SC_HTTPS_KNOWN_HOSTS="$KH_FRESH" \
      "$SC" clone "$URL" "$W/clone_strict_fail" 2>"$W/strict.err"; then
    fail "strict mode against an unpinned host should have refused the clone"
  fi
  grep -q "SC_HTTPS_STRICT" "$W/strict.err" \
    || fail "strict refusal must mention SC_HTTPS_STRICT: $(cat "$W/strict.err")"
  [ ! -e "$KH_FRESH" ] || fail "a strict refusal must not write a pin file"
  echo "SC_HTTPS_STRICT=1, unpinned host: refused, no pin file written ✔"

  SC_HTTPS_STRICT=1 SC_HTTPS_FINGERPRINT="$FPR" SC_HTTP_TOKEN="$TOKEN" SC_HTTPS_KNOWN_HOSTS="$KH_FRESH" \
    "$SC" clone "$URL" "$W/clone_prepin" >/dev/null
  [ ! -e "$KH_FRESH" ] || fail "SC_HTTPS_FINGERPRINT pre-pin must never persist to the known_hosts file"
  echo "SC_HTTPS_FINGERPRINT pre-pin: strict clone succeeded, still no pin file written ✔"

  echo
  echo "=== [$run_label] 6: server key swap -> pin mismatch hard-fails ==="
  kill "$SERVER_PID"
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
  ! nc -z 127.0.0.1 "$PORT" 2>/dev/null || fail "server still accepting connections after kill"
  rm -rf "$ORIGIN/.sc/serve-tls"

  PORT2="$(pick_port)"
  "$SC" serve --http "127.0.0.1:$PORT2" --tls "$ORIGIN" \
    >"$W/server2.out" 2>"$W/server2.err" &
  SERVER_PID=$!
  wait_for_port "$PORT2"
  wait_for_line "$W/server2.out" "^listening on 127.0.0.1:$PORT2\$"
  wait_for_line "$W/server2.out" "tls fingerprint: sha256:"
  FPR2="$(grep "tls fingerprint:" "$W/server2.out" | awk '{print $3}')"
  [ "$FPR2" != "$FPR" ] || fail "restarted server minted the same fingerprint — key swap didn't happen"
  echo "server restarted on a fresh port with a NEW identity: $FPR2 (differs from $FPR) ✔"

  # Pin the OLD fingerprint against the NEW server's address, simulating a
  # client that connected to this host:port before the key changed.
  KH_MISMATCH="$W/known_hosts_mismatch"
  printf '127.0.0.1:%s %s\n' "$PORT2" "$FPR" > "$KH_MISMATCH"
  URL2="sc+https://127.0.0.1:$PORT2/"
  if SC_HTTP_TOKEN="$TOKEN" SC_HTTPS_KNOWN_HOSTS="$KH_MISMATCH" \
      "$SC" clone "$URL2" "$W/clone_mismatch" 2>"$W/mismatch.err"; then
    fail "a pin mismatch must hard-fail the clone"
  fi
  grep -q "does not match the pinned fingerprint" "$W/mismatch.err" \
    || fail "mismatch error must say 'does not match the pinned fingerprint': $(cat "$W/mismatch.err")"
  grep -qF "$KH_MISMATCH" "$W/mismatch.err" \
    || fail "mismatch error must name the pin file: $(cat "$W/mismatch.err")"
  echo "pin mismatch: clone refused, error names the mismatch and the pin file ✔"

  kill "$SERVER_PID"
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""

  echo
  echo "=== [$run_label] 7: tightened plaintext public-bind gate — tokens alone no longer justify it ==="
  PORT3="$(pick_port)"
  if "$SC" serve --http "0.0.0.0:$PORT3" "$ORIGIN" 2>"$W/gate.err"; then
    fail "a plaintext non-loopback bind justified only by tokens should now be refused"
  fi
  grep -q -- "--tls" "$W/gate.err" \
    || fail "the refusal must name --tls as the fix: $(cat "$W/gate.err")"
  echo "0.0.0.0 bind, tokens configured, no --tls: refused, error names --tls ✔"

  "$SC" serve --http "0.0.0.0:$PORT3" --tls "$ORIGIN" \
    >"$W/gate_ok.out" 2>"$W/gate_ok.err" &
  SERVER2_PID=$!
  wait_for_port "$PORT3"
  wait_for_line "$W/gate_ok.out" "^listening on "
  echo "0.0.0.0 bind, tokens configured, --tls: accepted ✔"
  kill "$SERVER2_PID"
  wait "$SERVER2_PID" 2>/dev/null || true
  SERVER2_PID=""
  ! nc -z 127.0.0.1 "$PORT3" 2>/dev/null || fail "gate server still accepting connections after kill"

  echo
  echo "=== [$run_label] 8: zero .sc/tmp residue anywhere ==="
  check_no_tmp_residue "$ORIGIN" "origin"
  check_no_tmp_residue "$W/clone" "clone"
  check_no_tmp_residue "$W/clone2" "clone2"
  check_no_tmp_residue "$W/clone_prepin" "clone_prepin"
  echo "origin + every clone: zero .sc/tmp residue ✔"

  cd "$W"
  rm -rf "$W"
  W=""

  echo
  echo "RESULT: ok"
}

run_demo "run 1"
run_demo "run 2 (repeatable, not a one-shot fluke)"
