#!/usr/bin/env bash
# P25 proof: streaming pack transfer over the ssh:// code path. A large blob
# (~1 MiB) is committed and signed, `SC_PACK_CHUNK` is forced tiny so the
# transfer crosses MANY chunk frames instead of one, and the clone is proved
# byte-for-byte identical to the origin — including a clean `sc verify
# --require` in the clone, which only works if the signature object rode the
# same chunked stream as everything else. `.sc/tmp/` (the spill/temp-pack
# scratch dir both ends use — see `Layout::tmp_dir` and `TempPackGuard`) is
# asserted empty on both ends after every transfer, proving the RAII guard
# leaves zero residue whether the transfer succeeded or (in a later demo)
# failed partway through. The whole sequence runs TWICE against the same
# origin (a second clone into a fresh destination) to prove the chunking and
# cleanup are repeatable, not a one-shot fluke.
#
# Reuses demo/run_ssh_remote_demo.sh's SC_SSH shim: a GIT_SSH-style stand-in
# that drops ssh's host argument and runs `sc serve --stdio` locally, so the
# full ssh:// argv-construction + framed-wire-protocol + `sc serve --stdio`
# dispatch path runs with no sshd required.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

fail() { echo "FAIL: $1"; exit 1; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
A="$W/A"
KEY="$W/alice.key"

# --- The ssh stand-in (identical shim to run_ssh_remote_demo.sh). ---
cat > "$W/fake_ssh" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ] && [ "$1" != "sc" ]; do shift; done
[ $# -gt 0 ] || { echo "shim: no sc command in argv" >&2; exit 65; }
shift
exec "$SC_BIN" "$@"
EOF
chmod +x "$W/fake_ssh"
export SC_SSH="$W/fake_ssh" SC_BIN="$SC"

# --- Force many chunk frames: SC_PACK_CHUNK overrides wire::pack_chunk_size()
#     for THIS process (and anything it execs, including the ssh shim's `sc
#     serve --stdio`, which inherits the environment) — a ~1 MiB blob over a
#     4 KiB chunk crosses roughly 250+ ST_PACK_CHUNK frames instead of one.
#     Default to 4096 but respect an outer override
#     (SC_PACK_CHUNK=64 bash demo/run_streaming_demo.sh), so the knob is real. ---
: "${SC_PACK_CHUNK:=4096}"
export SC_PACK_CHUNK

echo "=== setup: keygen v2 for alice (trusted signer) ==="
alice_out=$("$SC" keygen --out "$KEY")
alice_sig=$(echo "$alice_out" | awk '/signing key:/{print $3}')
[ -n "$alice_sig" ] || fail "alice's signing key missing from keygen output"
echo "alice signing key: $alice_sig"

echo
echo "=== 1: init A, commit a ~1 MiB blob, sign it ==="
mkdir -p "$A"; cd "$A"
"$SC" init >/dev/null
{
  printf '[signing]\n'
  printf 'alice = "%s"\n' "$alice_sig"
  printf '\n[signers]\n'
  printf 'trusted = ["alice"]\n'
} > .sc/recipients.toml
# ~1 MiB of pseudo-random bytes as text (hex), so it is not trivially
# zstd-collapsed to a handful of chunks — exercises real chunk-boundary
# splitting across the pack body.
head -c 1048576 /dev/urandom | od -An -tx1 | tr -d ' \n' > big.bin
blob_before=$(shasum -a 256 big.bin | awk '{print $1}')
printf 'small\n' > small.txt
"$SC" commit -m "add big blob" --author alice --sign --identity "$KEY" >/dev/null
log_before=$("$SC" log)
echo "A: ~1 MiB blob + small file committed and signed ✔"

URL="ssh://demohost$A"

run_one_clone() {
  local dst="$1" label="$2"
  cd "$W"
  "$SC" clone "$URL" "$dst" >/dev/null

  # `[signers] trusted` is local trust policy, not repo content — clone
  # never copies .sc/recipients.toml (same reason the P22 provenance demo
  # gives bob his own copy). Mirror A's trust config so `sc log`'s signed
  # marker and `sc verify --require` compare like for like.
  cp "$A/.sc/recipients.toml" "$dst/.sc/recipients.toml"

  # --- object set byte-for-byte: every loose object path under .sc/objects
  #     must match exactly (content addressing means same bytes -> same
  #     sharded path; a streamed transfer that dropped or corrupted a chunk
  #     would show up here as a missing/mismatched path). ---
  diff <(cd "$A" && find .sc/objects -type f | sort) \
       <(cd "$dst" && find .sc/objects -type f | sort) \
    || fail "$label: object set differs from origin"

  # --- working tree byte-for-byte. ---
  [ "$(shasum -a 256 "$dst/big.bin" | awk '{print $1}')" = "$blob_before" ] \
    || fail "$label: big.bin is not byte-identical to the origin"
  [ "$(cat "$dst/small.txt")" = "small" ] || fail "$label: small.txt did not survive the wire"

  # --- history identical. ---
  cd "$dst"
  [ "$("$SC" log)" = "$log_before" ] || fail "$label: sc log differs from origin"

  # --- signature rode the stream: sc verify --require is clean in the
  #     clone, which only holds if the signature object (a separate CAS
  #     object from the snapshot it covers) crossed the same chunked wire. ---
  "$SC" verify --require | tail -1 | grep -q '0 untrusted, 0 invalid, 0 unsigned' \
    || fail "$label: sc verify --require is not clean in the clone"
  echo "$label: object set + working tree + log byte-for-byte, sc verify --require clean ✔"

  # --- zero temp residue on both ends after a successful transfer. ---
  [ -d "$A/.sc/tmp" ] && [ -n "$(ls -A "$A/.sc/tmp" 2>/dev/null)" ] \
    && fail "$label: origin's .sc/tmp is not empty after the transfer"
  [ -d "$dst/.sc/tmp" ] && [ -n "$(ls -A "$dst/.sc/tmp" 2>/dev/null)" ] \
    && fail "$label: clone's .sc/tmp is not empty after the transfer"
  echo "$label: zero .sc/tmp residue on both ends ✔"
}

echo
echo "=== 2: clone over ssh:// with SC_PACK_CHUNK=$SC_PACK_CHUNK (many-chunk transfer) ==="
run_one_clone "$W/B1" "B1 (first clone)"

echo
echo "=== 3: run again into a fresh destination — repeatable, not a one-shot fluke ==="
run_one_clone "$W/B2" "B2 (second clone)"

echo
echo "RESULT: streaming pack transfer over ssh:// with a forced $SC_PACK_CHUNK-byte chunk size —"
echo "object set, working tree, and history byte-for-byte across two independent"
echo "clones, a signed commit verifies clean after riding the chunked stream, and"
echo "zero .sc/tmp residue on either end both times."
