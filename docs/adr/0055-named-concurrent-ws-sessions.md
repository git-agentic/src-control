# ADR-0055: Named and concurrent `sc ws` sessions (P20, #215)

- **Status:** Accepted (built, except workspace refresh, which is designed here and deferred)
- **Date:** 2026-10-20
- **Phase:** 20 (follow-on)
- **Builds on:** ADR-0030 (agent sessions), ADR-0050 (sessions on partial clones), ADR-0023 (agent workspaces), ADR-0043 (per-checkout protected cache)

## Context

ADR-0030 allows one unnamed session per repo: `sc ws fork` writes `.sc/ws/session.toml` and `.sc/ws/<i>/`, and refuses while a manifest exists. Two agent teams working on the same repo cannot each hold a session, and issue #215 asks for named, concurrently open sessions and a way to move a workspace onto a newer tip.

Reading the code turned up one fact that shapes the design. `Repo::open` takes the single-writer lock (`.sc/lock`) for the life of the process, and `sc ws run` spawned the agent command while its `Repo` was still open. While an agent ran in one workspace, every other `sc` command on the repo (`list`, `harvest`, `abandon`, another `run`) failed with `Locked`. Two sessions could exist on disk but not be used at the same time.

## Decisions

1. **Named sessions are additive.** `sc ws fork --name <n>` opens a session called `<n>`. Omitting `--name` addresses the unnamed session exactly as before. A name takes the branch-name grammar (`validate_branch_name`): it becomes a directory under `.sc/` and the prefix of the session's fallback branches. A name that is already open is refused with the existing "already open" message plus the name and the `abandon --session` command to run. Forking the unnamed session while only named ones are open is allowed, and the reverse too.

2. **Addressing.** A session is picked with `--session <n>` on `list`, `run`, `harvest` and `abandon`; a workspace inside it stays addressed by its index (`run <i>`, `abandon [<i>]`). With no `--session` the command means the unnamed session. It never guesses a named one: if only named sessions are open, the error lists them and says to pass `--session`. `sc ws list` with no flag prints every open session (the unnamed one first, then named ones sorted by name); the unnamed session's header line is unchanged.

3. **On-disk layout: no migration.** The unnamed session keeps `.sc/ws/session.toml`, `.sc/ws/<i>/` and `.sc/ws/cache-<i>`, byte for byte. A named session lives in a sibling root, `.sc/ws-<name>/`, with the same inner shape. A sibling and not a child, so every teardown (`remove_dir_all` of a session root on abandon, harvest end and fork-residue cleanup) touches only its own session, and no reserved names are needed inside a root. The manifest format is unchanged; the session name is derived from the directory and never stored. A `.sc/ws-*` directory without a manifest is crash residue and is ignored.
   - Downgrade hazard: a binary from before this change does not look at `.sc/ws-*`, so its `sc gc` would not root a named session's base snapshot. Do not run an old `sc` against a repo with named sessions open.

4. **Fallback branches and labels follow the name.** The unnamed session still falls back to `work-<i>`. A named session falls back to `<name>-<i>`, and `SC_WORKSPACE` is the same string, matching `sc work --name` and the ADR-0030 rule that the label equals the branch name. The existing collision suffix (`-2`, `-3`) still applies, so a clash across sessions (for example a session named `work`) cannot overwrite a branch. The candidate commit message is `ws-<i> harvest` (unnamed) or `ws <name>-<i> harvest`.

5. **Concurrency: serialized by the repo lock, with the lock released while an agent runs.**
   - Fork, harvest and abandon run under the repo lock for the whole command. Two harvests therefore never overlap; the second `sc` process gets `Locked` and nothing has changed. Each harvest builds its candidate from its own session's fork-time base and probes it against the landing tip as it is then, so the existing logic already covers "the branch moved on since fork". No new merge code.
   - **Outcome rule.** Within a session, workspaces land in ascending index order (ADR-0030). Across sessions, the order is the order the harvests are invoked: the first lands, a later one merges cleanly over it or, when its change conflicts, falls back to its own `<name>-<i>` branch and leaves the landing branch untouched. Disjoint edits land to the same tree in either order; overlapping edits go to whoever harvests first. There is no implicit ordering and no `harvest --all`; a script that wants a fixed order calls `harvest --session` in that order.
   - Each session has its own manifest, so no manifest is shared between sessions. Abandoning or harvesting one session never writes another's files.
   - **`sc ws run` no longer holds the lock while the command runs.** `Repo::ws_run_plan` resolves the live workspace, its label and (with `--with-secrets`) the decrypted environment under the lock; the CLI drops the repo and then spawns the command (`WsRunPlan::run`). Other sessions can be listed, harvested or abandoned meanwhile. `Repo::ws_run` stays as the two steps together for library callers.
   - Abandoning a workspace under a running agent removes its directory; the agent sees its files vanish. That is the caller's choice, as it was before.

6. **Protected caches.** `Layout::ws_cache_path(session, i)` is `<session root>/cache-<i>`, beside the checkout like before, so each session's stat caches live and die with that session. Nothing else about ADR-0043 changes: the cache is never committed or transferred, and a lost cache costs a re-seal, not correctness.

7. **Sparse view and partial clones.** Each session records the host's sparse spec in its own manifest at fork, and harvest diffs and commits against that recorded view (ADR-0030's fork-time rule, per session). ADR-0050 holds per session: fork fills the view or refuses with the gap error before anything is written, a harvest grafts out-of-view subtrees from its base, and landing uses the ADR-0049 merge. Two sessions forked under different host views each keep their own.

8. **gc.** Every open session's base snapshot is a gc root (`list_sessions`), not only the unnamed one.

9. **`sc work` is unchanged.** It uses temporary directories and never touches `.sc/ws*`.

## Workspace refresh (designed, not built)

`sc ws refresh <name>` would move a session onto the landing branch's newer tip while keeping the agents' work. The smaller design, recommended for a follow-up:

- For each live workspace, commit its checkout to a temporary candidate with the same pipeline harvest uses (scanner gate, protected re-encryption), so a scanner rejection refuses the refresh.
- Replay that candidate onto the new tip with the ADR-0049 tree engine (`tree_merge_filled`), in memory. Any conflict, in the view or not, refuses the whole refresh with the conflicting paths, and the session is untouched.
- Only when every workspace replays cleanly: re-materialize each checkout from its replayed tree under the session's recorded view, rewrite the manifest base to the new tip, then drop the temporary candidates. Order the manifest write after the checkouts, and keep the old checkouts until the new ones are complete, so a crash leaves either the old or the new state.

It is deferred, not rejected, for these reasons:

- The merge path is head-centric (ADR-0030, as-shipped note), so refresh needs a headless "merge a candidate into a tree" entry point plus "re-materialize a checkout from a tree while keeping unrelated files". Neither exists, and the second one rewrites files an agent may have open.
- Harvest already integrates work forked from an older base by three-way merge, so a stale base costs a possible fallback branch, not data. Abandon and re-fork covers the need to see newer code.
- The acceptance criteria for this issue (independent sessions, deterministic outcomes) do not depend on it, and refresh deserves its own crash-safety tests.

## Consequences

- Several named sessions can be open at once and used in parallel, including while an agent command runs, with deterministic first-harvest-wins outcomes.
- Existing repos and scripts keep working untouched: the unnamed layout, command lines, output, `work-<i>` names and manifests are the same.
- A harvest that finds the landing branch moved by another session's landing takes the ordinary merge path; conflicts end up as `<name>-<i>` branches for manual `sc merge`.
- Not built: refresh, `harvest --all`, and a per-entry record of the branch a workspace landed on (the existing `sc ws list` caveat about `--into` stands).

## Alternatives considered

- **Nest named sessions under `.sc/ws/<name>/`:** every `remove_dir_all(.sc/ws)` would take other sessions with it, and names would need reserving against `session.toml`, `cache-*` and digits. Rejected for the sibling root.
- **One manifest holding several sessions, base per workspace:** a schema change that needs a migration path and makes every manifest write a shared read-modify-write. Rejected.
- **Pick the only named session when no `--session` is given:** convenient, but a script's meaning would change when a second session is opened. Rejected for an explicit error.
- **A second lock for harvest instead of the repo lock:** the repo lock already serializes every writer and is held across the whole harvest. Rejected as redundant.
- **Make the lock re-entrant or per-session:** a much larger change to a core invariant. Releasing it around the child process is enough.

## Tests

`ws.rs`: named and unnamed sessions coexist in separate roots with their own cache paths; collisions and invalid names are refused; addressing a missing session lists what is open and never guesses; the first of two conflicting harvests wins and the second falls back to `<name>-1`, in both orders; disjoint sessions land to the same tree in either order; abandoning one session leaves another's checkout, edit and manifest intact and still runnable and harvestable; `SC_WORKSPACE` and fallback branches carry the name and are suffixed on a clash; gc roots every open base. `partial_sessions.rs`: two named sessions on a partial clone see only the view, land one after the other, and carry `docs/` unread. `crates/cli/tests/ws_sessions.rs`: the same through the binary, plus listing and harvesting another session from inside a running `sc ws run`. `demo/run_ws_demo.sh` gains a named-sessions section.
