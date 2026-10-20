# ADR-0050: Agent sessions on partial clones (P37d)

- **Status:** Accepted (built)
- **Date:** 2026-10-19
- **Phase:** 37d
- **Builds on:** ADR-0049 (merge on partial clones), ADR-0048 (presence-based partial clones), ADR-0034 (sparse checkouts), ADR-0030 (agent sessions), ADR-0023 (agent workspaces)

## Context

`sc ws fork`/`harvest` and `sc work` were refused on a partial clone (ADR-0037, kept by ADR-0048 and ADR-0049). Two reasons stood behind the refusal, and ADR-0049 removed the second:

1. A workspace is a whole checkout and a partial clone does not hold the whole tree.
2. Harvest lands a workspace by merging, and merge was unsupported.

ADR-0049 left sessions "undecided" as a product question. The question was whether an agent on a partial clone should be possible at all. This record answers it: yes, with the host's view as the agent's world. That is the point of a partial clone for a large repository, and parallel agents are the other half of the project's thesis.

## Decisions

1. **A workspace on a partial clone sees the host's sparse view and nothing else.** `sc ws fork` already inherits the host view (ADR-0034). `sc work` gave each agent the complete tree by design; on a partial clone there is no complete tree, so its agents get the host view too, the same as `sc ws`. This is the one behavioural difference between a full and a partial clone, and it is the documented contract: an agent cannot read or change what the clone does not hold. A user who wants agents to see more runs `sc sparse set` (a lazy clone fetches the widened view by id, ADR-0048) or `sc backfill --all`.

2. **The view is filled before anything is written.** Fork and `sc work` call `ensure_view` on the base tree: a lazy, online clone fetches the view closure by id, any other clone fails with `GapInView` and the `sc backfill <prefix>` hint, before a checkout, a manifest or a branch exists.

3. **Harvest bounds its tracked-path walk by the workspace's view on a partial clone.** The commit pipeline already grafts everything outside the view from the base snapshot (`snapshot_files`), so a workspace commit carries the out-of-view subtrees by id without reading them. Full clones keep their unbounded walk unchanged.

4. **Landing uses the ADR-0049 engine.** `ws_harvest` lands a clean workspace with `merge_with_identity`, which on a partial clone is the tree-recursive merge. The probe that decides "lands cleanly or falls back to `work-<i>`" is the same question answered by `tree_merge_filled` (`would_merge_cleanly_partial`): any conflict, inside the view or not, is "not clean", and the workspace becomes a `work-<i>` branch exactly as on a full clone. A conflict outside the view cannot arise from a workspace edit, which holds only the view, but it can arise from the host moving on; it falls back like any other.

5. **Nothing else changes.** The landing-branch rule (the one-session-per-repo rule was relaxed by ADR-0056, which keeps this ADR's view rules per session), `ws run`/`list`/`abandon`, scanner gating, protected-path carry and the oplog are unchanged. A `sc work` session still leaves no residue.

## Consequences

- Fork, run, harvest and abandon, and `sc work`, work on a partial clone, including a lazy one. Their results equal a full clone's for everything inside the view; outside it the result is the base's subtree, carried by id.
- The partial-clone refusal list shrinks to `sc export`, `sparse disable`, an empty `sparse set`, `sc rewrap`, `grant`/`revoke`, private branches, `sc push` to a git remote, and fetching from a remote other than the promisor origin.
- A host that moves on outside the workspace's view between fork and harvest lands without reading that region (carried), but a region both sides changed that the clone does not hold needs a lazy fetch or refuses with the gap error before any write, as for `sc merge`.

## Tests

`partial_sessions.rs`: fork lays out the view only; a clean harvest lands a two-parent merge and carries `docs/` unread; a same-line conflict falls back to `work-1` and leaves `main` alone; an untouched workspace is `Unchanged`; `sc work` agents cannot see `docs/`, commit to `agent-1`, leave `docs/` carried and unread, and leave no session residue.

## Open questions

1. A workspace on a lazy clone does not fetch on demand while an agent runs: the agent sees the view as it was filled at fork. Reading outside it is not possible by design (decision 1).
2. Sessions on a clone whose `.sc/sparse` is empty (a full view) are only meaningful if the filter covers the whole tree; otherwise `ensure_view` reports the gap.
