# Fix stale object-presence check in `run_protect_demo.sh`

**Issue:** [#44](https://github.com/git-agentic/src-control/issues/44) — `run_protect_demo.sh: stale pre-P8 object-presence check always fails`
**Date:** 2026-07-11
**Status:** Approved

## Problem

`demo/run_protect_demo.sh` fails on current main with `FAIL: clone dropped
object 06` (reproduced at HEAD). Lines 50–52 verify the clone received every
object by globbing `"$A"/.sc/objects/*` and testing each entry with `[ -f ]`.
That predates P8 (ADR-0015): the sharded loose-object layout stores objects as
`objects/<aa>/<rest>`, so the first glob level yields shard *directories* and
`[ -f ]` is always false — the check fails on the first entry, every run.

Everything before and after the broken loop passes: the ciphertext greps
(zstd-loose objects still expose the plaintext control marker), the
keyless-switch skip report, and the authorized decrypt.

## Fix

Replace the flat per-object loop with the sorted `find`-diff already used by
`demo/run_http_remote_demo.sh:107` and `demo/run_streaming_demo.sh:98`:

```bash
diff <(cd "$A" && find .sc/objects -type f | sort) \
     <(cd "$B" && find .sc/objects -type f | sort) \
  || fail "clone object store differs from origin"
```

This is deliberately a *stronger* assertion than the original: byte-path
equality of the two object stores in both directions, not just A ⊆ B. A full
local clone of a loose-only repo produces an identical store layout (proven by
the two sibling demos, which diff across the wire). On failure, `diff` prints
the differing paths before `fail` fires, so the failure is self-explaining.

The comment above the check is updated to state the new claim ("the clone's
object store matches the origin's exactly"). Nothing else in the script
changes.

### Alternatives considered

- **Two-level per-object loop** (`objects/*/*` with shard-relative paths):
  preserves the original one-way semantics but is a bespoke pattern; the
  find-diff is the established idiom in this demo suite.
- **Recursive file-count comparison** (partial-clone style): weakest — equal
  counts don't prove the same objects travelled. Only appropriate where
  partial-clone asymmetry makes equality impossible, which doesn't apply here.

## Scope

- `demo/run_protect_demo.sh` — one hunk (comment + loop → diff). No Rust code,
  tests, or other docs change; the demo is the test.

## Verification

Run `bash demo/run_protect_demo.sh` twice. Each run must print all four ✔
lines plus the final `RESULT:` line and exit 0; the mktemp workdir is removed
by the existing `trap`. The fix commit references and closes issue #44.
