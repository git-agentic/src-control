# P27 — Partial Clone Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sc clone --filter <prefix>` fetches and stores only in-prefix reachable objects; out-of-prefix objects are promisor gaps that `sc backfill` fills on demand, with no network in any read path (spec: `docs/superpowers/specs/2026-07-09-p27-partial-clone-design.md`, ADR-0037). Capstone of the P25–P27 scale horizon.

**Architecture:** One path-aware filtered reachability walk (`reachable.rs`) serves both the server (build a pack of only in-filter objects — out-of-filter children are pruned by choice, parent trees kept) and the client's gc/verify (out-of-filter children are absent but skipped by path BEFORE any `get()`, so there is no NotFound to tolerate — an in-filter absent object still errors = corruption). A `.sc/promisor` marker (filter + origin) records the partial state; `sc backfill` widens it. The gap error fires at a few explicit access sites (sparse-widen, merge-out-of-filter, export), never woven through every reader.

**Tech Stack:** Rust stable, existing crates, **no new dependencies**.

## Global Constraints

- Explicit backfill, **no network in any read path** — gc/verify/materialize/merge never fetch; a genuine out-of-filter access is a clear error pointing at `sc backfill` (spec).
- **One slice: partial ⊇ sparse.** `--filter` sets both `.sc/promisor` (durable fetch-filter) and `.sc/sparse` (mutable view); the filter uses P24/P7 `matching_prefix` boundary rules (spec).
- **The descent rule** (load-bearing): descend into / include a tree entry at path P iff `filter.matches(P)` (P is in-filter) OR the filter has a prefix strictly under P (P is an ANCESTOR of an in-filter path — must descend to reach it). A BLOB entry is included iff `filter.matches(P)`. Out-of-filter subtree/blob entries are skipped — their objects are never added, so on the client they're never `get()`'d (spec's "referenced-but-absent").
- **Gap vs corruption is path-checked**: an absent object whose path is out-of-filter is an expected gap; in-filter absent IS corruption (spec).
- Wire: `GetPack` gains an optional filter field; `PROTOCOL_VERSION` bumps 2→3, both ends v3, handshake rejects mismatch (spec). A full (filter-absent) `get_pack` is behaviorally identical to today.
- `sc export` refuses on a partial clone; transparent lazy-fetch, size filters, and git-bridge partial are OUT of scope (spec).
- No new dependencies; tests next to code; disk tests clean up and assert removal (CLAUDE.md).

---

### Task 1: `.sc/promisor` marker + `PromisorFilter` (+ ROADMAP flip)

**Files:**
- Create: `crates/repo/src/promisor.rs`
- Modify: `crates/repo/src/lib.rs` (register + re-export), `crates/repo/src/layout.rs` (`promisor_path()`, mirroring `sparse_path`)
- Modify: `ROADMAP.md` (Active → P27; mirror the P26 Task-1 flip)

**Interfaces (produced, consumed by Tasks 2–5):**
```rust
/// A partial clone's durable marker: the fetch-filter prefixes + the
/// promisor remote (origin URL). Absent file = a full clone.
pub struct Promisor { prefixes: Vec<String>, pub origin: String }
impl Promisor {
    /// P24/P7 boundary match: is `path` inside the filter?
    pub fn matches(&self, path: &str) -> bool;
    /// Should the walk descend into a tree at `path`? True if the path is
    /// in-filter OR some filter prefix lies strictly under it (ancestor).
    pub fn should_descend(&self, path: &str) -> bool;
    pub fn prefixes(&self) -> &[String];
    /// Widen the filter to also include `prefixes` (backfill). Dedups.
    pub fn widen(&mut self, prefixes: &[String]);
}
pub fn load(layout: &Layout) -> Result<Option<Promisor>>;   // None = full clone
pub fn store(layout: &Layout, p: &Promisor) -> Result<()>;  // atomic write
impl Repo { pub fn promisor(&self) -> Result<Option<Promisor>>; }
```
File format (`.sc/promisor`): line 1 `origin <url>`, then one prefix per line. Atomic write (the `atomic_write_durable` the other `.sc/` state uses).

- [ ] **Step 1: ROADMAP flip.**
- [ ] **Step 2: Failing tests** (promisor.rs in-module): `matches_boundary` (filter `["src/"]`: `src/a`→true, `src`→true, `srcfoo`→false, `docs/x`→false — mirror `Sparse`'s boundary test); `should_descend_includes_ancestors` (filter `["src/app/"]`: `should_descend("src")`→true (ancestor of src/app), `should_descend("src/app")`→true (in-filter), `should_descend("docs")`→false, `matches("src")`→false (ancestor is not IN-filter)); `store_load_round_trip` (origin + prefixes round-trip; absent file → None); `widen_dedups`. Reuse `Sparse`/`protect::matching_prefix` for `matches`; `should_descend` = `matches(path) || self.prefixes.iter().any(|p| p.trim_end_matches('/').starts_with(&format!("{}/", path)))` (a prefix lies under path) — plus the empty-path root always descends.
- [ ] **Step 3: Implement.** **Step 4: Run** `cargo test -p scl-repo promisor` + `cargo test` → green. **Step 5: Commit** — `git commit -am "feat(repo): .sc/promisor marker + PromisorFilter (matches + ancestor-aware should_descend) (P27)"`

---

### Task 2: the path-aware filtered reachability walk

**Files:**
- Modify: `crates/repo/src/reachable.rs`

**Interfaces (produced, consumed by Tasks 3 & 5):**
```rust
/// The prefix predicate the filtered walk needs — implemented by Promisor
/// (Task 1) AND Sparse, so both can drive it. (Define a small trait or take
/// `&Promisor` directly — implementer's call; state it.)
pub trait PrefixFilter { fn matches(&self, path: &str) -> bool; fn should_descend(&self, path: &str) -> bool; }

/// Like `reachable_objects`, but when a filter is given, prune out-of-filter
/// subtrees/blobs: include a parent tree (structure + child ids) but do NOT
/// recurse into / include an out-of-filter child. Returns the included set
/// AND the gap ids (out-of-filter child ids referenced but excluded).
pub fn reachable_objects_filtered(
    src: &mut impl ObjectSource,
    tips: &[ObjectId],
    filter: Option<&dyn PrefixFilter>,
) -> Result<Reachable>;
pub struct Reachable { pub included: BTreeSet<ObjectId>, pub gaps: BTreeSet<ObjectId> }
```
- Consumes: Task 1's `Promisor` (impls `PrefixFilter`).

- [ ] **Step 1: Failing tests** (reachable.rs in-module; build a multi-subtree repo via the existing test idiom — a root tree with `src/` and `docs/` subtrees each holding a blob; grep the existing `reaches_snapshots_trees_blobs_and_secrets` test for the VfsRepo idiom):
  - `filtered_prunes_out_of_prefix_subtree`: filter `["src/"]` → `included` has the snapshot, root tree, the `src` subtree, and `src`'s blob; `included` does NOT have the `docs` subtree object or `docs`'s blob; `gaps` contains the `docs` subtree id (referenced by the root tree but excluded).
  - `filtered_keeps_ancestor_trees`: a deep repo `src/app/x` with filter `["src/app/"]` → root tree, `src` tree, `src/app` tree, and `x` blob are all included (ancestors descended); a sibling `src/other/y` is a gap.
  - `filter_none_is_strict_unchanged`: `reachable_objects_filtered(.., None)` equals today's `reachable_objects` output (no gaps) — the regression guard that the full path is untouched.
  - `in_filter_absent_is_an_error`: on a source missing an IN-filter object, the filtered walk `get()`s it and errors (corruption) — NOT swallowed as a gap.
- [ ] **Step 2: Implement.** Add a path-tracking stack: each stack item is `(tree_id, path)`. Snapshot root is at path `""`. For each entry at `child_path = if path.is_empty() { name } else { format!("{path}/{name}") }`: if `filter` is None → today's behavior (include+recurse). If Some(f): a Blob → include iff `f.matches(child_path)` else add to `gaps`; a Tree → if `f.should_descend(child_path)` include+push `(id, child_path)`, else add to `gaps` (referenced, not descended). The snapshot walk (parents, secrets, root) is unchanged; only tree descent gains the filter. Keep the existing `reachable_objects`/`walk_tree` as the `filter=None` fast path (or route them through the new fn — DRY, state which). NOTE: out-of-filter children are added to `gaps` by ID from the PARENT tree entry, never `get()`'d — so on a client where they're absent, no NotFound occurs.
- [ ] **Step 3: Run** `cargo test -p scl-repo reachable` + `cargo test` → green (gc/get_pack still pass — they still call the unfiltered path). **Step 4: Commit** — `git commit -am "feat(repo): path-aware filtered reachability walk — prune out-of-filter subtrees, keep parents, collect gaps (P27)"`

---

### Task 3: prefix-scoped get_pack + wire filter field + PROTOCOL_VERSION 3

**Files:**
- Modify: `crates/repo/src/transport.rs` (`Transport::get_pack` + `build_pack_tempfile` gain a filter; `LocalTransport`)
- Modify: `crates/repo/src/wire.rs` (`GetPack` filter field; `PROTOCOL_VERSION = 3`; serve + the client threading)
- Modify: `crates/repo/src/stdio_transport.rs` / `http_transport.rs` (client get_pack passes the filter through — both wrap `WireClient`, so the change is in `WireClient::get_pack`)
- Modify: `crates/repo/src/sync.rs` (call sites gain a `filter: Option<&[String]>` arg, defaulting None)

**Interfaces:**
```rust
// Transport::get_pack gains a filter:
fn get_pack(&self, wants: &[ObjectId], haves: &[ObjectId], filter: Option<&[String]>, out: &mut dyn Write) -> Result<()>;
```
- Consumes: Task 2 (`reachable_objects_filtered`), Task 1 (`Promisor` as the filter carrier — but the wire carries raw prefix strings; the server rebuilds a `Promisor`-like `PrefixFilter` from them).

- [ ] **Step 1: Failing tests:**
  - `filtered_get_pack_excludes_out_of_prefix` (transport.rs, LocalTransport direct): seed a remote with `src/a` + `docs/b`; `get_pack(wants=[tip], haves=[], filter=Some(["src/"]))` into a temp; ingest into a fresh store; assert the `src/a` blob is present and the `docs/b` blob is NOT (`store.contains` false), while the root tree + snapshot ARE present.
  - `filtered_get_pack_over_wire` (stdio_transport.rs, via the in-process client↔serve harness): same, driven through the `GetPack` wire field with `filter=Some(["src/"])` — proves the field round-trips and the server filters.
  - `handshake_rejects_v2_peer`: adapt the existing version-skew test to `PROTOCOL_VERSION = 3`.
  - `full_get_pack_unchanged`: `filter=None` transfers everything (regression).
- [ ] **Step 2: Implement.** `build_pack_tempfile(wants, haves, filter)`: build a `PrefixFilter` from the prefixes (a `Promisor`-with-empty-origin or a lightweight wrapper) and pass to `reachable_objects_filtered`; the have-set is computed UNFILTERED (haves are full-reachable — you exclude everything the client has). The signature over-send seam (P22) is unchanged. `GetPack` encode/decode: after `haves`, write the filter as a `u32` prefix-count + strings (0 = None). `serve`'s GetPack arm passes the decoded filter to `build_pack_tempfile`. `WireClient::get_pack` sends the filter. `PROTOCOL_VERSION = 3`. Update every `get_pack` call site (sync.rs, tests) to the new arity (None where unfiltered).
- [ ] **Step 3: Run** `cargo test -p scl-repo` + `cargo test` + `bash demo/run_ssh_remote_demo.sh` + `bash demo/run_http_remote_demo.sh` + `bash demo/run_streaming_demo.sh` → all green (full transfers undisturbed; both transports still round-trip at v3). **Step 4: Commit** — `git commit -am "feat(repo): prefix-scoped get_pack + GetPack filter wire field, PROTOCOL_VERSION 3 (P27)"`

---

### Task 4: `sc clone --filter` + `.sc/promisor` + `sc backfill` + push round-trip

**Files:**
- Modify: `crates/repo/src/sync.rs` (`clone_url` gains a filter → writes `.sc/promisor` + `.sc/sparse`; a `backfill` fn)
- Modify: `crates/cli/src/main.rs` (`Clone` gains `--filter <prefix>` repeated; new `Backfill { prefixes }` command)

**Interfaces:**
```rust
// sync.rs:
pub fn clone_url_filtered(src_url: &str, dst: impl AsRef<Path>, filter: Option<&[String]>) -> Result<Repo>;
impl Repo {
    /// Read `.sc/promisor`, prefix-scoped-fetch `prefixes` from the origin,
    /// ingest, and widen `.sc/promisor`. Errors if not a partial clone.
    pub fn backfill(&self, prefixes: &[String]) -> Result<()>;
}
```
- Consumes: Tasks 1–3.

- [ ] **Step 1: Failing tests** (sync.rs tests, over LOCAL path AND sc+http loopback — reuse the P26 loopback harness for one of them):
  - `partial_clone_omits_out_of_filter_objects`: `clone_url_filtered(src, dst, Some(["src/"]))`; the dst store has `src/`'s blob but NOT `docs/`'s (`store.contains` false); `.sc/promisor` exists (origin + `src/`); `.sc/sparse` == `["src/"]`.
  - `partial_clone_commit_and_push_round_trips`: in the partial clone, edit `src/a`, commit (carries `docs/` subtree id via P24 carry WITHOUT touching the gap object — verify the commit succeeds and its snapshot's root tree still references the original `docs/` id), push back to the origin; assert the origin tip advanced and a full clone of the origin sees the `src/` edit AND the intact `docs/`.
  - `backfill_makes_out_of_filter_present`: after the partial clone, `repo.backfill(&["docs/".into()])`; now `store.contains(docs_blob)` true; `.sc/promisor` widened to include `docs/`.
  - `backfill_on_full_clone_errors`: `.sc/promisor` absent → `backfill` errors clearly.
- [ ] **Step 2: Implement.** `clone_url_filtered`: the existing clone flow but `get_pack(.., filter)`; after ingest, `promisor::store(origin=src_url, prefixes=filter)` and `sparse::store(filter)`. `backfill`: `promisor::load` (err if None); `open_transport(promisor.origin)`; `get_pack(wants=local tips, haves=local reachable-present-set, filter=Some(new prefixes), out=temp)`; ingest; `promisor.widen(new); promisor::store`. CLI: `Clone { .., #[arg(long)] filter: Vec<String> }` → `clone_url_filtered(.., (!filter.is_empty()).then_some(&filter))`; `Backfill { prefixes: Vec<String> }` → `repo.backfill(&prefixes)`. Guard: `--filter` with a git-bridge URL (http(s)://, scp) errors "partial clone unsupported over git remotes" (out of scope).
- [ ] **Step 3: Run** `cargo test -p scl-repo` + `cargo test -p scl-cli` + `cargo test` → green. **Step 4: Commit** — `git commit -am "feat(repo,cli): sc clone --filter + .sc/promisor + sc backfill; partial-clone push round-trips (P27)"`

---

### Task 5: gap-tolerant gc + verify + the gap error (the data-safety task)

**Files:**
- Modify: `crates/repo/src/gc.rs` (reachability uses the filtered walk when `.sc/promisor` present)
- Modify: `crates/cli/src/main.rs` (`run_verify` reports partial gaps; export refuse; the sparse-widen preflight in `run_sparse`)
- Modify: `crates/repo/src/repo.rs` / `sparse.rs` (`set_sparse`/`disable_sparse` preflight against the partial filter; the merge/replay out-of-filter gap error)
- Modify: `crates/gitio` export entry OR `crates/cli` export command (refuse on partial clone)

**Interfaces:** Consumes Tasks 1–2.

- [ ] **Step 1: Failing tests:**
  - `gc_on_partial_clone_preserves_and_doesnt_error` (gc.rs): a partial clone (promisor `["src/"]`, `docs/` a gap); `gc::run` → succeeds (no NotFound error), prunes nothing that's reachable, and the `src/` objects survive; a genuinely-unreachable PRESENT loose object is still pruned (gc still works). Critically: gc does NOT error trying to walk the `docs/` gap.
  - `gc_in_filter_missing_object_still_errors_or_is_absent`: (adjudicate the exact behavior — a partial clone should never have an in-filter object missing; if one is, that's corruption. A cheap assertion: the filtered gc walk on a healthy partial clone reaches all in-filter present objects.)
  - `verify_reports_partial_not_corrupt` (repo/cli level): on a partial clone, verify reports the out-of-filter gaps as expected (a "partial: N objects outside filter" line), exit 0; it does NOT report them as missing/corrupt.
  - `sparse_widen_beyond_partial_errors_with_backfill_hint`: partial `["src/"]`, sparse `["src/"]`; `set_sparse(["docs/"])` (or `disable_sparse`) → error naming `docs/` and `sc backfill`, BEFORE materializing (preflight); no partial write.
  - `export_refuses_on_partial_clone`: `sc export` (or the export fn) on a `.sc/promisor` repo → clear error pointing at backfill-to-full.
- [ ] **Step 2: Implement.** gc: if `promisor::load` is Some, compute `reachable` via `reachable_objects_filtered(store, &roots, Some(&promisor))` (the `.included` set) — out-of-filter children are skipped by path, never `get()`'d, so no NotFound; the decided-root walks stay as-is (in-filter). verify: after the existing sig walk, run the filtered walk to count `gaps`, print the partial line. `set_sparse`/`disable_sparse`: preflight — if `promisor` is Some and any requested sparse prefix is NOT within the partial filter (`!promisor.matches` for the prefix, i.e. widening beyond what's fetched), return the gap error before touching disk. merge/replay: where a content-merge/materialize would read an out-of-filter object, map `Error::NotFound` → the gap error (a `partial_gap_hint(path)` helper); since sparse ⊆ partial gates most reads, this fires only on genuine out-of-filter merge content. export: refuse up front if `promisor::load` is Some.
- [ ] **Step 3: Run** `cargo test -p scl-repo` + `cargo test -p scl-cli` + `cargo test` + `bash demo/run_history_demo.sh` + `bash demo/run_sparse_demo.sh` → green (full-clone gc/verify/sparse/merge undisturbed — the filtered paths only engage when `.sc/promisor` is present). **Step 4: Commit** — `git commit -am "feat(repo,cli): gap-tolerant gc + partial-aware verify; gap error on sparse-widen/merge/export outside the filter (P27)"`

---

### Task 6: Demo + docs + horizon close-out

**Files:**
- Create: `demo/run_partial_clone_demo.sh` (mode 755)
- Modify: `docs/adr/0037-partial-clone.md` (→ Accepted + refinements, code-verified — the descent/ancestor rule, the one-walk-serves-both insight, gap-vs-corruption path check, the gap-error sites, push-composes verification), `docs/adr/README.md` (0037 → Accepted), `ROADMAP.md` (P27 → Done + BOTH a `## Done` narrative bullet AND the completed-phases table row; Active → "None — the P25–P27 scale-&-reach horizon is complete; brainstorm the next horizon"), `CLAUDE.md` (commands: `sc clone --filter`, `sc backfill`; a `**Phase 27 is built.**` paragraph WITH the no-network-in-read-paths / export-refuses / partial⊇sparse boundaries)

- [ ] **Step 1: Demo** (house style; reuse the sparse/http demos' idioms). Sequence: init a source repo with `src/` `docs/` `lib/` subtrees (each a file, make `docs/`/`lib/` blobs distinctively large-ish); commit; serve it (local path is simplest, or `sc serve --http` on a loopback port); `sc clone --filter src/ <src-or-url> <dst>`; PROVE `docs/`/`lib/` objects are UNFETCHED by inspecting the dst object store (e.g. count objects, or assert the specific out-of-filter blob content hash is absent — `sc verify` reporting gaps, or a `find .sc/objects` object-count delta vs a full clone); edit + commit in `src/` and push back, assert it lands (a full re-clone sees the edit + intact docs/lib); `sc backfill docs/` and prove `docs/` objects are now present (verify gaps decreased / the blob is now readable); `sc gc` on the partial clone succeeds and preserves everything; zero residue. Run twice.
- [ ] **Step 2: Docs** (P26-completion commit shape; refinements: the ancestor descent rule, the single filtered walk serving server+client, the path-checked gap-vs-corruption distinction, the enumerated gap-error sites, the push-composes-via-carry verification, PROTOCOL_VERSION 3).
- [ ] **Step 3: Full verification** — `cargo test && bash demo/run_partial_clone_demo.sh && bash demo/run_ssh_remote_demo.sh && bash demo/run_http_remote_demo.sh && bash demo/run_streaming_demo.sh && bash demo/run_sparse_demo.sh && bash demo/run_provenance_demo.sh && git diff main -- '*Cargo.toml'` (all green; empty dep diff; the transport + sparse + provenance demos are the regression gates; run_protect_demo.sh pre-P8 failure known — skip).
- [ ] **Step 4: Commit** — `git commit -am "docs+demo: accept ADR-0037 partial clone; P25–P27 scale horizon complete (P27)"`
