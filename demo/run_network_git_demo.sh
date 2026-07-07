#!/usr/bin/env bash
# P18 demo: network git remotes over file:// through the mirror bridge.
# Proves the full collaborative loop through a real network-shaped URL (not
# a bare local path): clone adopts the hub's default branch, push lands on
# the HUB (not just the local mirror), a second clone picks up the pushed
# work, a fetch+merge closes the loop both directions, and the local mirror
# is disposable reconstructible state — deleting it doesn't lose anything a
# fetch can't recover.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the success line.
set -euo pipefail

# Build once and resolve the binary to an absolute path BEFORE we cd away.
cargo build --bin sc >/dev/null 2>&1
SC="$(pwd)/target/debug/sc"

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

fail() { echo "FAIL: $1"; exit 1; }

HUB="$ROOT/hub.git"; SEED="$ROOT/seed"; REPO1="$ROOT/repo1"; REPO2="$ROOT/repo2"

# --- 1: a bare hub, seeded with one commit via a scratch git worktree. ---
git init -q --bare -b main "$HUB"
git init -q -b main "$SEED"
printf 'hello from the hub\n' > "$SEED/seed.txt"
git -C "$SEED" add seed.txt
git -C "$SEED" -c user.name=seed -c user.email=seed@example.com commit -q -m "seed"
git -C "$SEED" push -q "$HUB" main
echo "1: bare hub seeded with one commit ✔"

url="file://$HUB"

# --- 2: sc clone auto-detects the file:// URL as a network git remote. ---
"$SC" clone "$url" "$REPO1" >/dev/null
head1="$(cat "$REPO1/.sc/HEAD")"
[ "$head1" = "ref: refs/heads/main" ] || fail "repo1's branch must match the hub's default (main), got: $head1"
[ "$(cat "$REPO1/seed.txt")" = "hello from the hub" ] || fail "seeded file did not survive the clone"
echo "2: sc clone (no --git flag) adopted the hub's default branch, seeded file present ✔"

# --- 3: commit new work in repo1, push over the network, hub (not mirror) sees it. ---
( cd "$REPO1" && printf 'work from repo1\n' > from-repo1.txt && "$SC" commit -m "from repo1" --author repo1 >/dev/null )
push_out="$(cd "$REPO1" && "$SC" push origin)"
case "$push_out" in *pushed*) ;; *) fail "push must report a pushed-commit summary, got: $push_out" ;; esac
hub_log="$(git -C "$HUB" log --oneline main)"
case "$hub_log" in *"from repo1"*) ;; *) fail "the HUB (not just the local mirror) must show repo1's push" ;; esac
echo "3: sc push origin landed on the hub itself ✔"

# --- 4: a second clone picks up the pushed commit. ---
"$SC" clone "$url" "$REPO2" >/dev/null
[ -f "$REPO2/from-repo1.txt" ] || fail "repo2's clone must include repo1's pushed file"
[ "$(cat "$REPO2/from-repo1.txt")" = "work from repo1" ] || fail "repo2's copy of the pushed file has the wrong content"
echo "4: sc clone (second clone) picked up repo1's pushed commit ✔"

# --- 5: full collaborative loop — repo2 commits + pushes, repo1 fetches + merges. ---
( cd "$REPO2" && printf 'work from repo2\n' > from-repo2.txt && "$SC" commit -m "from repo2" --author repo2 >/dev/null )
( cd "$REPO2" && "$SC" push origin >/dev/null )
( cd "$REPO1" && "$SC" fetch origin >/dev/null && "$SC" merge origin/main >/dev/null )
[ "$(cat "$REPO1/from-repo2.txt")" = "work from repo2" ] || fail "repo1 must have repo2's file after fetch + merge"
echo "5: repo2 push -> repo1 fetch + merge closed the collaborative loop ✔"

# --- 5b: a repeat push with no new work reports already-up-to-date. ---
repeat_out="$(cd "$REPO2" && "$SC" push origin)"
case "$repeat_out" in *"already up to date"*) ;; *) fail "a repeat push with no new work should report already up to date, got: $repeat_out" ;; esac
echo "5b: repeat sc push origin reports already up to date ✔"

# --- 6: mirror reconstructibility — the local mirror is disposable; the
#     marks map (identity across the two DAGs) is NOT and must survive. ---
[ -f "$REPO1/.sc/git-remotes/origin/marks" ] || fail "expected a marks map at .sc/git-remotes/origin/marks"
rm -rf "$REPO1/.sc/git-remotes/origin/mirror.git"
( cd "$REPO1" && "$SC" fetch origin >/dev/null ) || fail "sc fetch must succeed after the local mirror is deleted"
[ -f "$REPO1/.sc/git-remotes/origin/marks" ] || fail "the marks map must still exist after mirror reconstruction"
echo "6: deleting the local mirror is safe — sc fetch reconstructs it from the hub ✔"

echo
echo "P18 PROOF COMPLETE: network git remotes over file:// — clone auto-detects"
echo "the hub's default branch, push lands on the hub itself (not just a local"
echo "mirror), a second clone and a fetch+merge close the collaborative loop in"
echo "both directions, and the local mirror is reconstructible disposable state."
echo
echo "Real-GitHub recipe (same commands, no file:// scaffolding):"
echo "  sc remote add origin git@github.com:org/repo.git --git"
echo "  sc push origin"
echo "Auth: git must be on PATH and able to authenticate itself (ssh-agent for"
echo "git@ URLs, a credential helper for https:// URLs) — sc shells out to your"
echo "system git for the network leg and does not manage credentials itself."
