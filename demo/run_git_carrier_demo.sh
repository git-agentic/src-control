#!/usr/bin/env bash
# P39 demo: `sc+git::<git-url>` remotes (ADR-0060). A Git repository carries a
# native sc store as `refs/sc/*`, so private branches, protected paths and
# secrets travel through a Git host, which the Git bridge cannot do (it refuses
# sealed content). Run first against a bare Git repo on disk (file://), then
# against a real sc-forge on loopback HTTP. Proves end-to-end:
#
#   1. BRIDGE LIMIT: public `main` mirrors into the repository as an ordinary
#      Git branch through a `--git` remote, and the same bridge refuses the
#      branch once it holds a protected path and a secret.
#   2. GATE: pushing a private branch to an `sc+git::` remote is refused before
#      any upload (nothing changes under refs/sc/*) until the remote is added
#      with --allow-private-branches; protected paths and secrets need no opt-in.
#   3. CARRIER: `git ls-remote` lists refs/sc/*; a plain `git clone` of the same
#      repository fetches none of them and holds no sc objects.
#   4. COMPACT: `sc remote compact` works on the carrier. A Git host reports no
#      trustworthy object age, so the first run only records when it first saw
#      each object (refs/sc/compact/sightings) and deletes nothing; a second run
#      a grace window later deletes what aged, with leased ref deletions. The
#      refs/sc/* count is printed before and after, and the clones below prove
#      the compacted store still reads.
#   5. KEYLESS: an sc clone sees `hotfix (private, no access)`, no protected
#      plaintext, no embargoed file, and cannot read the secret value.
#   6. KEYED: an sc clone with alice's identity reads the protected file, the
#      secret and the embargoed branch.
#   7. SERVE: `sc serve --http --store sc+git::<host>` in front of the same host.
#      A public push and a keyless clone work through it; a private push is
#      refused by the SERVER (no private-branch object reaches the host) until
#      the operator restarts it with --allow-private-branches.
#   8. FILTERED READ: every manifest fetch sc makes (traced through an SC_GIT
#      shim with GIT_TRACE_PACKET) sends `ref-prefix refs/sc/manifest`, and the
#      host lists that one ref, not its branches or the other refs/sc/* keys.
#   9. Zero residue: no leftover `sc-git-bucket-*` temp dirs (TMPDIR is private
#      to each run, so any leftover is ours), nothing in the serve home's
#      .sc/tmp and no .sc/tmp residue.
#
# Self-checking: every claim is an assertion; any failure exits non-zero before
# the RESULT line. Run twice to prove repeatability. The forge leg needs
# `sc-forge` (unix only), curl and python3 (for a free port); SKIP_FORGE=1
# skips it. Auth to the forge goes through a temporary GIT_CONFIG_GLOBAL with
# `http.extraHeader` (a password in the URL is refused by sc+git::).
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
TARGET="${CARGO_TARGET_DIR:-$PWD/target}"
SC="$TARGET/debug/sc"
FORGE=""
if [ "${SKIP_FORGE:-0}" != "1" ]; then
  if cargo build --quiet --bin sc-forge 2>/dev/null; then
    FORGE="$TARGET/debug/sc-forge"
  else
    echo "note: sc-forge did not build (unix only); skipping the forge leg"
  fi
fi

tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"

fail() { echo "FAIL: $1"; exit 1; }

WORK=""
FORGE_PID=""
SERVE_PID=""
SERVE_ADDR=""
cleanup() {
  if [ -n "$SERVE_PID" ]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
    SERVE_PID=""
  fi
  if [ -n "$FORGE_PID" ]; then
    kill "$FORGE_PID" 2>/dev/null || true
    wait "$FORGE_PID" 2>/dev/null || true
    FORGE_PID=""
  fi
  if [ -n "$WORK" ]; then rm -rf "$WORK"; WORK=""; fi
}
trap cleanup EXIT

SENT_FILE="PROD-ENV-SENTINEL-4c1e"
SENT_EMBARGO="EMBARGOED-FIX-SENTINEL-4c1e"
SENT_MSG="EMBARGOED-MESSAGE-SENTINEL-4c1e"
SENT_SECRET="SECRET-VALUE-SENTINEL-4c1e"

# No sc-git-bucket-* directory may outlive the sc process that made it.
no_cache_residue() {
  if ls "$WORK/tmp" 2>/dev/null | grep -q '^sc-git-bucket-'; then
    fail "leftover sc-git-bucket-* temp dir in $WORK/tmp"
  fi
}

# start_serve <home> <store url> [extra sc serve flags]: runs `sc serve --http`
# on a free loopback port in the background; sets SERVE_PID and SERVE_ADDR.
start_serve() {
  local home="$1" store="$2" i
  shift 2
  : > "$WORK/serve.out"
  "$SC" serve --http 127.0.0.1:0 --store "$store" "$@" "$home" \
    > "$WORK/serve.out" 2> "$WORK/serve.err" &
  SERVE_PID=$!
  SERVE_ADDR=""
  for i in $(seq 1 100); do
    SERVE_ADDR=$(sed -n 's/^listening on //p' "$WORK/serve.out" | head -1)
    [ -n "$SERVE_ADDR" ] && return 0
    kill -0 "$SERVE_PID" 2>/dev/null || { cat "$WORK/serve.err"; fail "sc serve exited"; }
    sleep 0.1
  done
  fail "sc serve did not announce an address"
}

# wait_serve_idle <home>: every session removes its Git cache when it ends, but
# the client can return before the server thread has finished; wait for that so
# killing the server cannot leave a cache behind (a killed server's leftovers
# are only reaped by the next start).
wait_serve_idle() {
  local i
  for i in $(seq 1 100); do
    [ -z "$(ls -A "$1/.sc/tmp" 2>/dev/null)" ] && return 0
    sleep 0.1
  done
  fail "the server's sessions did not clean up under $1/.sc/tmp"
}

stop_serve() {
  if [ -n "$SERVE_PID" ]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
    SERVE_PID=""
  fi
}

# scenario <label> <index> <git url of the carrier repo> <dump host objects? 1|0>
scenario() {
  local label="$1" idx="$2" giturl="$3" dump="$4"
  local url="sc+git::$giturl"
  local a="$WORK/alice-$idx"
  local key="$WORK/alice.key"
  local out before mid after n

  echo
  echo "=== [$label] 1: public main goes through the Git bridge; sealed content cannot ==="
  mkdir -p "$a" && cd "$a"
  "$SC" init >/dev/null
  printf '[recipients]\nalice = "%s"\n' "$ALICE_PK" > .sc/recipients.toml
  echo "public readme" > README.md
  "$SC" commit -m "public base" --author alice >/dev/null
  "$SC" remote add mirror "$giturl" --git >/dev/null
  "$SC" push mirror >/dev/null || fail "public main must mirror to Git"
  git ls-remote "$giturl" refs/heads/main | grep -q "refs/heads/main" \
    || fail "the host must carry main as an ordinary Git branch"
  # Now add what the bridge cannot carry: a protected path, a secret, a private branch.
  "$SC" protect config/ --to alice >/dev/null
  mkdir -p config
  echo "DB=$SENT_FILE" > config/prod.env
  "$SC" secret add API_TOKEN --to alice --value "$SENT_SECRET" >/dev/null
  "$SC" commit -m "main base" --author alice --identity "$key" >/dev/null
  "$SC" branch hotfix --private --to alice --identity "$key" >/dev/null
  "$SC" switch hotfix --identity "$key" >/dev/null
  echo "$SENT_EMBARGO" > embargo.txt
  "$SC" commit -m "$SENT_MSG" --author alice --identity "$key" >/dev/null
  "$SC" switch main --identity "$key" >/dev/null
  out=$("$SC" push mirror 2>&1 || true)
  echo "$out" | grep -q "refusing to export encrypted content" \
    || fail "the Git bridge must refuse a branch with sealed content (got: $out)"
  echo "main mirrored as a Git branch; the bridge now refuses sealed content ✔"

  echo
  echo "=== [$label] 2: GATE — the private branch needs the per-remote opt-in ==="
  out=$("$SC" remote add origin "$url" 2>&1 >/dev/null) || fail "remote add must accept $url"
  echo "$out" | grep -q "everyone who can read the Git repository" \
    || fail "remote add must print the exposure notice (got: $out)"
  "$SC" push origin >/dev/null \
    || fail "pushing main (protected path + secret) needs no extra opt-in"
  git ls-remote "$giturl" | grep -q "refs/sc/manifest" \
    || fail "the push must store refs/sc/manifest on the Git host"
  before=$(git ls-remote "$giturl" 'refs/sc/*' | sort)
  "$SC" switch hotfix --identity "$key" >/dev/null
  out=$("$SC" push origin 2>&1 || true)
  echo "$out" | grep -q -- "--allow-private-branches" \
    || fail "a private push without the opt-in must be refused and name the flag (got: $out)"
  after=$(git ls-remote "$giturl" 'refs/sc/*' | sort)
  [ "$before" = "$after" ] || fail "the refused push must upload nothing"
  "$SC" remote add opted "$url" --allow-private-branches >/dev/null 2>&1
  "$SC" push opted >/dev/null || fail "a private push must work on the opted-in remote"
  "$SC" switch main --identity "$key" >/dev/null
  n=$(git ls-remote "$giturl" 'refs/sc/*' | wc -l | tr -d ' ')
  [ "$n" -gt 3 ] || fail "expected the store under refs/sc/* (got $n refs)"
  echo "refused without the opt-in (nothing uploaded), pushed with it; $n refs/sc/* on the host ✔"

  echo
  echo "=== [$label] 3: CARRIER — plain Git sees none of the sc store ==="
  git clone -q "$giturl" "$WORK/plain-$idx" 2>/dev/null || fail "plain git clone must work"
  [ "$(cat "$WORK/plain-$idx/README.md")" = "public readme" ] \
    || fail "the plain clone must hold the mirrored public main"
  if git -C "$WORK/plain-$idx" for-each-ref | grep -q "refs/sc"; then
    fail "a plain git clone must not fetch refs/sc/*"
  fi
  manifest_oid=$(git ls-remote "$giturl" refs/sc/manifest | cut -f1)
  [ -n "$manifest_oid" ] || fail "manifest ref must be listed by git ls-remote"
  if git -C "$WORK/plain-$idx" cat-file -e "$manifest_oid" 2>/dev/null; then
    fail "the plain clone must not hold the sc store's objects"
  fi
  [ ! -e "$WORK/plain-$idx/config" ] || fail "no protected path in the plain clone"
  if [ "$dump" = "1" ]; then
    # Host side: no plaintext of anything sealed in any object on the hub.
    git -C "${giturl#file://}" cat-file --batch-all-objects --batch > "$WORK/hub-dump-$idx"
    for s in "$SENT_FILE" "$SENT_EMBARGO" "$SENT_MSG" "$SENT_SECRET"; do
      if grep -aq "$s" "$WORK/hub-dump-$idx"; then fail "sealed plaintext $s found on the Git host"; fi
    done
    rm -f "$WORK/hub-dump-$idx"
  fi
  echo "git ls-remote lists refs/sc/*; plain clone holds main only, no sc objects ✔"

  echo
  echo "=== [$label] 4: COMPACT — two runs a grace window apart shrink refs/sc/* ==="
  cd "$a"
  before=$(git ls-remote "$giturl" 'refs/sc/*' | wc -l | tr -d ' ')
  out=$("$SC" remote compact opted --prune-expire 2s --allow-short-grace 2>&1) \
    || fail "the first compaction run failed (got: $out)"
  echo "$out" | grep -q "first sighting" \
    || fail "the first run must record when it first saw each object (got: $out)"
  echo "$out" | grep -q "deleted 0 log entries, 0 checkpoint(s), 0 pack(s)" \
    || fail "the first run must delete nothing it never saw before (got: $out)"
  git ls-remote "$giturl" refs/sc/compact/sightings | grep -q "refs/sc/compact/sightings" \
    || fail "the age record must be on the Git host"
  mid=$(git ls-remote "$giturl" 'refs/sc/*' | wc -l | tr -d ' ')
  sleep 3
  out=$("$SC" remote compact opted --prune-expire 2s --allow-short-grace 2>&1) \
    || fail "the second compaction run failed (got: $out)"
  echo "$out" | grep -q "deleted 0 log entries" \
    && fail "the second run, past the grace, must delete log entries (got: $out)"
  after=$(git ls-remote "$giturl" 'refs/sc/*' | wc -l | tr -d ' ')
  [ "$after" -lt "$mid" ] || fail "the second run must remove refs (before $before, mid $mid, after $after)"
  git ls-remote "$giturl" refs/sc/manifest | grep -q "refs/sc/manifest" \
    || fail "compaction must never remove the manifest"
  echo "refs/sc/*: $before before, $mid after run 1 (nothing deleted, first sightings recorded), $after after run 2 ✔"

  echo
  echo "=== [$label] 5: KEYLESS — an sc clone sees ciphertext and markers only ==="
  "$SC" clone "$url" "$WORK/keyless-$idx" >/dev/null 2>&1 || fail "keyless sc clone must work"
  cd "$WORK/keyless-$idx"
  "$SC" branch list | grep -q "hotfix (private, no access)" \
    || fail "keyless clone must see the private branch only as a marker"
  [ "$(cat README.md)" = "public readme" ] || fail "public content must be readable"
  [ ! -e config/prod.env ] || fail "protected path must be absent without the key"
  [ ! -e embargo.txt ] || fail "private path must never materialize"
  "$SC" secret list | grep -q API_TOKEN || fail "secret name must be listed"
  out=$("$SC" run -- sh -c 'printf "[%s]" "${API_TOKEN-}"' 2>&1 || true)
  echo "$out" | grep -q "$SENT_SECRET" && fail "keyless clone must not read the secret value"
  for s in "$SENT_FILE" "$SENT_EMBARGO" "$SENT_MSG" "$SENT_SECRET"; do
    if grep -r "$s" . >/dev/null 2>&1; then fail "plaintext $s leaked into the keyless clone"; fi
  done
  echo "keyless clone: branch marker, no protected plaintext, secret unreadable ✔"

  echo
  echo "=== [$label] 6: KEYED — alice's clone reads all three ==="
  "$SC" clone "$url" "$WORK/keyed-$idx" --allow-private-branches >/dev/null 2>&1 \
    || fail "keyed sc clone must work"
  cd "$WORK/keyed-$idx"
  grep -q "allow_private_branches = true" .sc/config || fail "clone --allow-private-branches must persist the opt-in"
  "$SC" switch main --identity "$key" >/dev/null
  [ "$(cat config/prod.env)" = "DB=$SENT_FILE" ] || fail "keyed clone must decrypt the protected file"
  "$SC" run --identity "$key" -- sh -c "test \"\$API_TOKEN\" = $SENT_SECRET" \
    || fail "keyed clone must inject the secret"
  "$SC" switch hotfix --identity "$key" >/dev/null
  [ "$(cat embargo.txt)" = "$SENT_EMBARGO" ] || fail "keyed clone must read the private branch"
  "$SC" log --identity "$key" | grep -q "$SENT_MSG" || fail "keyed clone must read the private log"
  echo "keyed clone: protected file decrypts, secret injects, embargoed branch reads ✔"

  echo
  echo "=== [$label] 7: SERVE — sc serve --store sc+git:: in front of the host ==="
  local home="$WORK/serve-home-$idx" after2
  mkdir -p "$home" && ( cd "$home" && "$SC" init >/dev/null )
  cd "$a"
  start_serve "$home" "$url"
  "$SC" remote add gated "sc+http://$SERVE_ADDR/x" >/dev/null 2>&1
  echo "public via server" > served.txt
  "$SC" commit -m "public via server" --author alice --identity "$key" >/dev/null
  before=$(git ls-remote "$giturl" 'refs/sc/*' | sort)
  "$SC" push gated >/dev/null || fail "a public push through the server must work"
  after=$(git ls-remote "$giturl" 'refs/sc/*' | sort)
  [ "$before" != "$after" ] || fail "the public push through the server must reach the host"
  "$SC" switch hotfix --identity "$key" >/dev/null
  echo "more embargoed" > embargo2.txt
  "$SC" commit -m "embargo via server" --author alice --identity "$key" >/dev/null
  before="$after"
  out=$("$SC" push gated 2>&1 || true)
  echo "$out" | grep -q -- "--allow-private-branches" \
    || fail "the server must refuse the private push and name its flag (got: $out)"
  echo "$out" | grep -q "No private-branch object was uploaded" \
    || fail "the server's refusal must say no private-branch object was uploaded (got: $out)"
  after=$(git ls-remote "$giturl" 'refs/sc/*' | sort)
  [ "$before" = "$after" ] || fail "the refused private push must leave refs/sc/* on the host unchanged"
  wait_serve_idle "$home"
  stop_serve
  start_serve "$home" "$url" --allow-private-branches
  "$SC" remote add opted-srv "sc+http://$SERVE_ADDR/x" >/dev/null 2>&1
  "$SC" push opted-srv >/dev/null || fail "the private push must work once the operator opted in"
  after2=$(git ls-remote "$giturl" 'refs/sc/*' | sort)
  [ "$before" != "$after2" ] || fail "the private push must reach the host with the flag"
  "$SC" switch main --identity "$key" >/dev/null
  "$SC" clone "sc+http://$SERVE_ADDR/x" "$WORK/srv-keyless-$idx" >/dev/null 2>&1 \
    || fail "a keyless clone through the server must work"
  ( cd "$WORK/srv-keyless-$idx" && "$SC" branch list | grep -q "hotfix (private, no access)" ) \
    || fail "a keyless clone through the server must see the private branch only as a marker"
  wait_serve_idle "$home"
  stop_serve
  echo "gated server: public push ok, private push refused (host unchanged); with the operator's flag it lands ✔"

  echo
  echo "=== [$label] 8: FILTERED READ — a manifest fetch asks the host for one ref ==="
  local trace="$WORK/trace-$idx" f refs nrefs fetches=0
  mkdir -p "$trace"
  SC_GIT="$WORK/sc-git-trace" TRACE_DIR="$trace" \
    "$SC" clone "$url" "$WORK/traced-$idx" >/dev/null 2>&1 || fail "the traced clone must work"
  nrefs=$(git ls-remote "$giturl" | wc -l | tr -d ' ')
  for f in "$trace"/manifest-*.log; do
    [ -e "$f" ] || continue
    grep -q 'ref-prefix refs/sc/manifest' "$f" \
      || fail "a manifest fetch must ask for the ref by prefix ($f)"
    refs=$(grep 'fetch<' "$f" | grep -o ' refs/[^ ]*$' | sort -u | tr -d ' ' | tr '\n' ' ')
    [ "$refs" = "refs/sc/manifest " ] \
      || fail "the host must list only refs/sc/manifest in a manifest fetch, got: $refs"
    fetches=$((fetches + 1))
  done
  [ "$fetches" -ge 1 ] || fail "no manifest fetch was traced"
  # Show the evidence: the request prefix and the ref listing the host answered with.
  f=$(ls "$trace"/manifest-*.log | head -1)
  grep -E 'fetch> ref-prefix refs/sc/manifest$|fetch< [0-9a-f]{40} refs/' "$f" \
    | sed 's/^[^ ]* *pkt-line.c:[0-9]* *packet: */    /'
  echo "$fetches manifest fetch(es) traced: each sent 'ref-prefix refs/sc/manifest' and the host listed refs/sc/manifest alone, though it holds $nrefs refs ✔"

  echo
  echo "=== [$label] 9: zero residue ==="
  no_cache_residue
  for r in "$a" "$WORK/keyless-$idx" "$WORK/keyed-$idx" "$WORK/srv-keyless-$idx" "$WORK/traced-$idx"; do
    if [ -d "$r/.sc/tmp" ] && [ -n "$(ls -A "$r/.sc/tmp" 2>/dev/null)" ]; then
      fail "$r/.sc/tmp is not empty"
    fi
  done
  echo "no sc-git-bucket-* temp dir, no .sc/tmp residue (serve home included) ✔"
}

start_forge() {
  local port data pw tok i
  port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
  data="$WORK/forge-data"
  mkdir -p "$data" && chmod 700 "$data"
  pw=$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')
  printf '%s\n' "$pw" | "$FORGE" admin user create --data-dir "$data" --username siteadmin \
    --password-stdin --email siteadmin@example.invalid --admin --must-change-password=false >/dev/null
  tok=$("$FORGE" admin user generate-access-token --data-dir "$data" --username siteadmin \
    --token-name demo --scopes all --raw | tail -1)
  "$FORGE" serve --data-dir "$data" --listen "127.0.0.1:$port" \
    --public-url "http://127.0.0.1:$port" > "$WORK/forge.log" 2>&1 &
  FORGE_PID=$!
  for i in $(seq 1 50); do
    curl -fs "http://127.0.0.1:$port/api/healthz" >/dev/null 2>&1 && break
    kill -0 "$FORGE_PID" 2>/dev/null || { cat "$WORK/forge.log"; fail "sc-forge exited"; }
    sleep 0.2
  done
  curl -fs "http://127.0.0.1:$port/api/healthz" >/dev/null || fail "sc-forge did not come up"
  curl -fs -X POST -H "Authorization: token $tok" -H 'Content-Type: application/json' \
    -d '{"name":"carrier","default_branch":"main"}' \
    "http://127.0.0.1:$port/api/v1/user/repos" >/dev/null || fail "forge repo creation failed"
  # Auth for both `git` and the git that sc+git:: spawns: a header, never a URL password.
  printf '[http "http://127.0.0.1:%s/"]\n\textraHeader = Authorization: token %s\n' \
    "$port" "$tok" > "$WORK/forge.gitconfig"
  FORGE_URL="http://127.0.0.1:$port/siteadmin/carrier.git"
}

run_demo() {
  local run_label="$1"
  WORK=$(mktemp -d "$tmp_base/sc-git-carrier-demo.XXXXXX")
  mkdir -p "$WORK/home" "$WORK/tmp"
  # SC_GIT shim: GIT_TRACE_PACKET is scrubbed from the environment sc hands git,
  # so the shim sets it, for manifest fetches only, one trace file per call.
  cat > "$WORK/sc-git-trace" <<'SHIM'
#!/bin/sh
case " $* " in
  *" +refs/sc/manifest:refs/sc/manifest "*) export GIT_TRACE_PACKET="$TRACE_DIR/manifest-$$.log" ;;
esac
exec git "$@"
SHIM
  chmod +x "$WORK/sc-git-trace"
  export HOME="$WORK/home"
  export TMPDIR="$WORK/tmp"     # any sc-git-bucket-* left behind lands here
  export GIT_CONFIG_NOSYSTEM=1
  export GIT_TERMINAL_PROMPT=0
  export GIT_CONFIG_GLOBAL=/dev/null
  export GIT_AUTHOR_NAME=demo GIT_AUTHOR_EMAIL=demo@example.invalid
  export GIT_COMMITTER_NAME=demo GIT_COMMITTER_EMAIL=demo@example.invalid

  "$SC" keygen --out "$WORK/alice.key" > "$WORK/alice.out" 2>&1
  ALICE_PK=$(grep -o 'scl-pk-[0-9a-f]*' "$WORK/alice.out" | head -1)

  git init --bare -q -b main "$WORK/hub.git"
  scenario "$run_label, bare repo file://" 1 "file://$WORK/hub.git" 1

  if [ -n "$FORGE" ]; then
    start_forge
    GIT_CONFIG_GLOBAL="$WORK/forge.gitconfig" \
      scenario "$run_label, sc-forge http://" 2 "$FORGE_URL" 0
    kill "$FORGE_PID" 2>/dev/null || true
    wait "$FORGE_PID" 2>/dev/null || true
    FORGE_PID=""
  fi
  no_cache_residue
  cd "$tmp_base"
  cleanup
}

run_demo "run 1"
run_demo "run 2 (repeatable, not a one-shot fluke)"

echo
echo "RESULT: a plain Git repository (a bare repo on disk, and a real sc-forge"
echo "over HTTP) carried a native sc store as refs/sc/*: a protected path, a"
echo "secret and a private branch crossed it losslessly, where the Git bridge"
echo "refuses sealed content. The private branch needed the per-remote"
echo "--allow-private-branches opt-in (the refused push uploaded nothing); a plain"
echo "git clone fetched no refs/sc/* and held no sc objects while public main"
echo "rode along as an ordinary Git branch. sc remote compact then shrank"
echo "refs/sc/* on the host in two runs a grace window apart (the first only"
echo "recorded first sightings and deleted nothing), and after it a keyless sc"
echo "clone saw only the branch marker and ciphertext, a keyed clone read all"
echo "three. An sc serve --store sc+git:: in front of the same host took public"
echo "pushes and refused a private push itself (no private-branch object reached"
echo "the host) until its operator passed --allow-private-branches; every"
echo "manifest fetch asked for one ref and the host listed that ref alone."
echo "Verified across two independent runs, zero sc-git-bucket-* or .sc/tmp"
echo "residue."
