# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

This repo has **no `CONTEXT.md`** (yet). Its domain language and conventions
currently live in two root files — treat them as the glossary/context source:

- **`CLAUDE.md`** at the repo root — the working guide: what this project is,
  the crate layout + dependency rule, the core invariants, the command surface,
  and a condensed capability map (one entry per phase, linking to the ADR that
  carries the authoritative domain vocabulary for that area). `AGENTS.md` is a
  pointer to it. The full per-phase narrative log is archived at
  `docs/archive/claude-md-phase-log-2026-07.md`.
- **`ARCHITECTURE.md`** at the repo root — the full design and rationale.
- **`docs/adr/`** — 43+ ADRs (0001…) recording every significant decision;
  read the ADRs that touch the area you're about to work in. This is a
  single-context repo, so there are no per-crate `crates/<name>/docs/adr/`
  dirs — all decisions live in the one root `docs/adr/`.
- **`CONTEXT.md`** at the repo root — does not exist today. If `/domain-modeling`
  later creates one, read it first and prefer its glossary.

If a file above doesn't exist, **proceed silently** — don't flag its absence or
suggest creating it upfront. `/domain-modeling` creates `CONTEXT.md` lazily when
terms actually get resolved.

## File structure

Single-context repo:

```
/
├── CLAUDE.md        ← working guide + capability map (AGENTS.md points here)
├── ARCHITECTURE.md  ← full design + rationale
├── docs/adr/        ← 0001…0043+ architectural decisions (one root collection)
└── crates/          ← core, vfs, gitio, crypto, tlsio, repo, cli (one cohesive VCS domain)
```

(This is a seven-crate Rust workspace but **one** domain — a next-gen VCS — so a
single context, not a multi-context `CONTEXT-MAP.md` layout.)

## Use the project's vocabulary

When your output names a domain concept (an issue title, a refactor proposal, a
hypothesis, a test name), use the term as it appears in `CLAUDE.md`/`ARCHITECTURE.md`
and the ADRs — e.g. *snapshot*, *protected path*, *promisor gap*, *sparse view*,
*worktree*, *escrow*, *wrapped DEK*. Don't drift to synonyms the docs avoid.

If the concept you need isn't documented yet, that's a signal — either you're
inventing language the project doesn't use (reconsider) or there's a real gap
(note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than
silently overriding:

> _Contradicts ADR-0025 (protected merge & replay) — but worth reopening because…_
