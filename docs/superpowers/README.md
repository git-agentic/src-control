# docs/superpowers — historical process artifacts

Everything under `specs/` and `plans/` is a **point-in-time process artifact**:
the brainstorm/spec and the implementation plan for a phase, written *before*
that phase was built. Every phase documented here has since shipped.

**Do not treat these files as current.** They contain pre-decision analysis,
rejected options, and drafts that the final implementation deliberately
diverged from. If you land here from a search: the code, the ADRs
(`docs/adr/`), and `CLAUDE.md`/`ARCHITECTURE.md` are authoritative; where this
directory disagrees with them, this directory is wrong (or was superseded
during the build — the ADR records the final decision).

They are kept because they document *how* each decision was reached, and
because the phase process (`ROADMAP.md`) references them.
