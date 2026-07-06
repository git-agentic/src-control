#!/usr/bin/env bash
# Headline proof for P12 (network transport over SSH): clone/push/fetch run
# against an ssh:// remote through the FULL ssh code path — URL parsing, argv
# construction, framed wire protocol, `sc serve --stdio` dispatch — with a
# GIT_SSH-style SC_SSH shim standing in for ssh, so no sshd is required and
# the proof is self-contained. Confidentiality rides along: a protected path
# crosses the wire as ciphertext an unauthorized clone cannot read.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the success line.
set -euo pipefail
cargo build --bin sc >/dev/null 2>&1
SC="$(pwd)/target/debug/sc"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
A="$W/A"; B="$W/B"; C="$W/C"; D="$W/D"; KEY="$W/alice.key"

SECRET_PLAINTEXT="TOP_SECRET_wire_password_hunter2"
PUBLIC_MARKER="PUBLIC_WIRE_MARKER_xyz"

fail() { echo "FAIL: $1"; exit 1; }

# --- The ssh stand-in: drops ssh's host argument and runs the requested
#     `sc serve` locally. Everything else is the real ssh:// code path. ---
cat > "$W/fake_ssh" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ] && [ "$1" != "sc" ]; do shift; done
[ $# -gt 0 ] || { echo "shim: no sc command in argv" >&2; exit 65; }
shift
exec "$SC_BIN" "$@"
EOF
chmod +x "$W/fake_ssh"
export SC_SSH="$W/fake_ssh" SC_BIN="$SC"

# --- A: the "server" repo — one plain public file to start. ---
mkdir -p "$A"; cd "$A"
"$SC" init >/dev/null
printf '%s\n' "$PUBLIC_MARKER" > README.md
"$SC" commit -m "initial" --author server >/dev/null
echo "A: repo with a public file ✔"

URL="ssh://demohost$A"

# --- Clone over ssh:// into B. ---
cd "$W"
"$SC" clone "$URL" "$B" >/dev/null
[ "$(cat "$B/README.md")" = "$PUBLIC_MARKER" ] || fail "public file did not survive the wire"
grep -q "$URL" "$B/.sc/config" || fail "origin does not record the ssh url"
echo "B: cloned over ssh:// — public content intact, origin records the url ✔"

# --- B commits and pushes back over the wire. ---
cd "$B"
printf 'from B\n' > b.txt
"$SC" commit -m "from-B" --author b >/dev/null
"$SC" push origin >/dev/null
cd "$A"
"$SC" log | grep -q "from-B" || fail "A's history lacks the pushed commit"
echo "B → A: push over ssh:// landed ✔"

# --- Racing writer: C clones, lands first; B's next push must be refused. ---
cd "$W"
"$SC" clone "$URL" "$C" >/dev/null
cd "$C"
printf 'from C\n' > c.txt
"$SC" commit -m "from-C" --author c >/dev/null
"$SC" push origin >/dev/null
cd "$B"
printf 'diverge\n' > d.txt
"$SC" commit -m "diverge-B" --author b >/dev/null
"$SC" push origin >/dev/null 2>&1 && fail "non-fast-forward push was not refused"
echo "B: divergent push refused (non-fast-forward) ✔"

# --- Recovery: fetch + merge + push. (Merge is clean by construction:
#     b.txt/c.txt/d.txt are distinct files and no protected path exists in
#     history yet.) ---
"$SC" fetch origin >/dev/null
"$SC" merge origin/main >/dev/null
"$SC" push origin >/dev/null
cd "$A"
"$SC" log | grep -q "diverge-B" || fail "A's history lacks the recovered push"
echo "B: fetch + merge + push recovered ✔"

# --- Confidentiality act: A protects a path and commits a secret file. ---
# NB: protect comes AFTER the merge scenario — kept for demo-flow clarity. (Historically P7's merge guard refused protected merges; P15/ADR-0025 lifted that, so the ordering is no longer load-bearing.)
cd "$A"
ALICE_PK="$(awk '/public key:/{print $3}' < <("$SC" keygen --out "$KEY"))"
printf '[recipients]\nalice = "%s"\n' "$ALICE_PK" > .sc/recipients.toml
"$SC" protect secret/ --to alice >/dev/null
mkdir -p secret
printf '%s\n' "$SECRET_PLAINTEXT" > secret/db.txt
"$SC" commit -m "add protected secret" --author server >/dev/null
grep -raq "$SECRET_PLAINTEXT" "$A/.sc/objects" && fail "plaintext leaked into A's object store"
grep -raq "$PUBLIC_MARKER" "$A/.sc/objects" || fail "positive control failed: public marker absent from A's objects"
echo "A: protected file committed as ciphertext (public marker present as positive control) ✔"

# --- Fresh unauthorized clone over ssh:// into D: ciphertext only. ---
cd "$W"
"$SC" clone "$URL" "$D" >/dev/null
[ -f "$D/secret/db.txt" ] && fail "unauthorized ssh clone wrote the protected file"
grep -raq "$SECRET_PLAINTEXT" "$D/.sc" && fail "plaintext crossed the wire"
[ "$(cat "$D/README.md")" = "$PUBLIC_MARKER" ] || fail "public file did not survive the wire to D"
echo "D: unauthorized clone over ssh:// — secret stays ciphertext, public content intact ✔"

echo
echo "P12 PROOF COMPLETE: sc-native transport over the ssh:// code path — clone,"
echo "push, fetch, CAS-guarded refs, and ciphertext-only confidentiality, with"
echo "zero sshd required."
