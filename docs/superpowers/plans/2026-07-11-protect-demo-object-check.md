# Fix Stale Object-Presence Check in `run_protect_demo.sh` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `demo/run_protect_demo.sh` pass again by replacing its pre-P8 flat object-presence loop with the sorted `find`-diff idiom used by the other demos (closes issue #44).

**Architecture:** The demo verifies a clone received every object by globbing `.sc/objects/*` and testing `[ -f ]`, but P8's sharded layout (`objects/<aa>/<rest>`) makes that first glob level directories, so the check always fails. Replace it with a byte-path equality diff of both stores' recursive file listings — the established pattern in `demo/run_http_remote_demo.sh:107` and `demo/run_streaming_demo.sh:98`.

**Tech Stack:** Bash (`set -euo pipefail` demo script), `find`, `diff`. No Rust code changes.

## Global Constraints

- Only `demo/run_protect_demo.sh` changes — no Rust code, tests, or other docs.
- The demo must remain self-checking: every claim an assertion, non-zero exit before the success line on any failure.
- The demo must leave zero residue (existing `mktemp -d` + `trap 'rm -rf "$W"' EXIT` handles this — do not touch it).
- Spec: `docs/superpowers/specs/2026-07-11-protect-demo-object-check-design.md`.

---

### Task 1: Replace the flat object loop with a find-diff store-equality check

**Files:**
- Modify: `demo/run_protect_demo.sh:48-52`

**Interfaces:**
- Consumes: nothing from other tasks (single-task plan).
- Produces: a passing `demo/run_protect_demo.sh` (exit 0, four ✔ lines + `RESULT:` line).

- [ ] **Step 1: Reproduce the failure (the "failing test")**

Run: `bash demo/run_protect_demo.sh; echo "exit=$?"`
Expected: prints `A: secret/db.txt committed as ciphertext (control file is plaintext-readable) ✔`, then `FAIL: clone dropped object <aa>` (a two-hex-char shard directory name, e.g. `06`), then `exit=1`.

- [ ] **Step 2: Apply the fix**

In `demo/run_protect_demo.sh`, replace these lines (currently 48–52):

```bash
# But the ciphertext blob did travel: every object reachable in A is present in B,
# and none of B's objects expose the plaintext.
for obj in "$A"/.sc/objects/*; do
  [ -f "$B/.sc/objects/$(basename "$obj")" ] || fail "clone dropped object $(basename "$obj")"
done
```

with:

```bash
# But the ciphertext blob did travel: the clone's object store matches the
# origin's exactly, and none of B's objects expose the plaintext.
diff <(cd "$A" && find .sc/objects -type f | sort) \
     <(cd "$B" && find .sc/objects -type f | sort) \
  || fail "clone object store differs from origin"
```

The surrounding lines (the `[ -f "$B/secret/db.txt" ]` check above, the `grep -raq "$SECRET_PLAINTEXT"` check below) stay untouched.

- [ ] **Step 3: Run the demo twice to verify it passes**

Run: `bash demo/run_protect_demo.sh && bash demo/run_protect_demo.sh; echo "exit=$?"`
Expected: each run prints all four ✔ lines ending with
`RESULT: protected path committed as ciphertext, unreadable in an unauthorized clone, decrypts only for the recipient ✔`, and the final `exit=0`.

- [ ] **Step 4: Commit**

```bash
git add demo/run_protect_demo.sh
git commit -m "fix(demo): sharded-layout object check in run_protect_demo.sh (closes #44)"
```
