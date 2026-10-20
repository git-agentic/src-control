//! `.sc/promisor` — a partial clone's durable fetch-filter marker (P27 Task 1).
//!
//! A `Promisor` records that this clone did not fetch every object: only
//! paths matching its `prefixes` were transferred, and the remainder is a
//! set of "promised" gaps the promisor `origin` remote can fill in later.
//! Absent file = a full clone (no gaps, nothing promised). Matching reuses
//! the same path-boundary discipline as [`crate::sparse::Sparse`] and
//! `protect.rs::matching_prefix` (P7/P24): a prefix without a trailing
//! slash matches its own bare path or any child under a `/` boundary, never
//! a sibling that merely shares a textual prefix.
//!
//! Beyond `Sparse::matches`, a partial-clone tree walk needs a second
//! predicate: whether to *descend* into a tree at all. A tree can be an
//! ancestor of an in-filter prefix without itself being in-filter (e.g.
//! filter `["src/app/"]`: `src` must be descended into to reach `src/app/`,
//! but `src` itself is not "in the filter"). [`Promisor::should_descend`]
//! is that ancestor-aware predicate; [`Promisor::matches`] stays the
//! narrower "is this path itself in-filter" check Task 2's object-emission
//! logic needs.
//!
//! Persistence: line 1 is `origin <url>`, then one prefix per line, written
//! atomically. This module only defines the marker + persistence +
//! matching; the filtered walk (Task 2), fetch-side filtering (Task 3),
//! backfill (Task 4), and gap-tolerant gc (Task 5) build on top of it.

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::repo::Repo;

/// Which paths a partial clone asked for (ADR-0055 B1). A size-only clone
/// (`--filter blob:limit=<size>` with no prefix) is in scope everywhere, which
/// an empty prefix list cannot say: that reads as "matches nothing".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Every path (a size-only clone).
    AllPaths,
    /// Only paths under these prefixes.
    Prefixes(Vec<String>),
}

/// A partial clone's durable marker: the fetch-filter scope + the optional
/// blob-size limit + the promisor remote (origin URL) that can fill in objects
/// outside the filter on demand. Absent file = a full clone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Promisor {
    scope: Scope,
    blob_limit: Option<u64>,
    pub origin: String,
}

impl Default for Promisor {
    fn default() -> Self {
        Promisor {
            scope: Scope::Prefixes(Vec::new()),
            blob_limit: None,
            origin: String::new(),
        }
    }
}

impl Promisor {
    /// Build a marker from an explicit origin + prefix list.
    pub fn new(origin: impl Into<String>, prefixes: Vec<String>) -> Self {
        Promisor {
            scope: Scope::Prefixes(prefixes),
            blob_limit: None,
            origin: origin.into(),
        }
    }

    /// Build a marker for a clone made with a blob-size limit (ADR-0055). An
    /// empty `prefixes` means every path is in scope ([`Scope::AllPaths`]).
    pub fn with_blob_limit(
        origin: impl Into<String>,
        prefixes: Vec<String>,
        blob_limit: u64,
    ) -> Self {
        Promisor {
            scope: if prefixes.is_empty() {
                Scope::AllPaths
            } else {
                Scope::Prefixes(prefixes)
            },
            blob_limit: Some(blob_limit),
            origin: origin.into(),
        }
    }

    /// The blob-size limit the clone was made with, if any: blobs of at least
    /// this many bytes, reachable only through history, were left out.
    pub fn blob_limit(&self) -> Option<u64> {
        self.blob_limit
    }

    /// True when every path is in scope (a size-only clone).
    pub fn is_all_paths(&self) -> bool {
        matches!(self.scope, Scope::AllPaths)
    }

    /// Whether `path` falls under any recorded prefix, at a `/` boundary —
    /// mirrors [`crate::sparse::Sparse::matches`] / `protect::matching_prefix`.
    /// An empty prefix list matches nothing (a degenerate partial clone);
    /// [`Scope::AllPaths`] matches everything. Callers gate on
    /// `Repo::promisor()` returning `None` for "no filter at all".
    pub fn matches(&self, path: &str) -> bool {
        match &self.scope {
            Scope::AllPaths => true,
            Scope::Prefixes(prefixes) => prefixes.iter().any(|p| {
                let bare = p.trim_end_matches('/');
                path == bare || path.starts_with(&format!("{bare}/"))
            }),
        }
    }

    /// Should a tree walk descend into `path`? True if `path` is itself
    /// in-filter, or some filter prefix lies strictly *under* `path` (i.e.
    /// `path` is an ancestor the walk must pass through to reach in-filter
    /// content deeper in the tree). The empty path (the root) always
    /// descends, since every prefix lies under it.
    pub fn should_descend(&self, path: &str) -> bool {
        match &self.scope {
            Scope::AllPaths => true,
            Scope::Prefixes(prefixes) => {
                path.is_empty()
                    || self.matches(path)
                    || prefixes
                        .iter()
                        .any(|p| p.trim_end_matches('/').starts_with(&format!("{path}/")))
            }
        }
    }

    /// The recorded prefixes, in the order they were set (empty for
    /// [`Scope::AllPaths`]).
    pub fn prefixes(&self) -> &[String] {
        match &self.scope {
            Scope::AllPaths => &[],
            Scope::Prefixes(prefixes) => prefixes,
        }
    }

    /// The filter as one line for messages: the prefixes, then `blob:limit=<n>`
    /// when the clone has a limit (`sc verify`, refusals).
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = self.prefixes().to_vec();
        if let Some(limit) = self.blob_limit {
            parts.push(format!("blob:limit={limit}"));
        }
        parts.join(", ")
    }

    /// Widen the filter to also include `prefixes` (backfill, Task 4).
    /// Dedups against the existing set; order is existing-then-new. An
    /// all-paths scope stays all-paths (nothing is wider).
    pub fn widen(&mut self, prefixes: &[String]) {
        if let Scope::Prefixes(existing) = &mut self.scope {
            for p in prefixes {
                if !existing.iter().any(|e| e == p) {
                    existing.push(p.clone());
                }
            }
        }
    }
}

/// The filter a `GetPack` carries (ADR-0037, ADR-0055): path prefixes and an
/// optional blob-size limit. The one place that decides whether a transfer is
/// filtered: a value exists only when it is active (`!prefixes.is_empty() ||
/// blob_limit.is_some()`), so every `Option<&PackFilter>` that is `Some` means
/// "partial transfer" on the sender, the bucket refusal and the client's
/// private-ref handling alike.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackFilter {
    prefixes: Vec<String>,
    blob_limit: Option<u64>,
}

impl PackFilter {
    /// `None` when neither a prefix nor a limit is given (a full transfer).
    pub fn new(prefixes: &[String], blob_limit: Option<u64>) -> Option<PackFilter> {
        (!prefixes.is_empty() || blob_limit.is_some()).then(|| PackFilter {
            prefixes: prefixes.to_vec(),
            blob_limit,
        })
    }

    /// The path prefixes; empty means every path.
    pub fn prefixes(&self) -> &[String] {
        &self.prefixes
    }

    /// Blobs of at least this many bytes that are not reachable from a want's
    /// own root tree are left out.
    pub fn blob_limit(&self) -> Option<u64> {
        self.blob_limit
    }

    /// The path scope as a [`Promisor`] the reachability walk can ask.
    pub(crate) fn scope(&self) -> Promisor {
        match self.blob_limit {
            Some(limit) => Promisor::with_blob_limit(String::new(), self.prefixes.clone(), limit),
            None => Promisor::new(String::new(), self.prefixes.clone()),
        }
    }
}

/// Split `sc clone --filter` values into path prefixes and the optional blob
/// limit (ADR-0055). A value starting with `blob:` is the reserved size
/// grammar, never a prefix: only `blob:limit=<size>` is accepted, once. A
/// path prefix that literally begins with `blob:` cannot be named here.
pub fn parse_clone_filters(values: &[String]) -> Result<(Vec<String>, Option<u64>)> {
    let mut prefixes = Vec::new();
    let mut limit = None;
    for v in values {
        let Some(spec) = v.strip_prefix("blob:") else {
            prefixes.push(v.clone());
            continue;
        };
        if spec == "none" {
            return Err(Error::InvalidArgument(
                "unsupported filter `blob:none`; use `blob:limit=0` to leave out every blob \
                 that no ref tip reaches"
                    .into(),
            ));
        }
        let Some(size) = spec.strip_prefix("limit=") else {
            return Err(Error::InvalidArgument(format!(
                "unsupported filter `{v}`; the only blob filter is `blob:limit=<size>` \
                 (`blob:` is reserved and cannot start a path prefix)"
            )));
        };
        if limit.is_some() {
            return Err(Error::InvalidArgument(
                "`blob:limit` given more than once; pass a single `--filter blob:limit=<size>`"
                    .into(),
            ));
        }
        limit = Some(scl_core::parse_byte_size(size).map_err(Error::InvalidArgument)?);
    }
    Ok((prefixes, limit))
}

/// Build the "outside this partial clone's fetch filter" error for `path`
/// (P27 Task 5) — used by the sparse-widen preflight
/// (`set_sparse`/`disable_sparse`), where `path` is a real prefix `sc
/// backfill <path>` can act on directly.
pub fn partial_gap_hint(path: &str) -> Error {
    Error::GapOutsideFilter(path.to_string())
}

/// The gap error for `path` on this partial clone: [`Error::GapBySize`] when
/// the clone has a blob-size limit and `path` is in its scope (the file's own
/// path is what `sc backfill` repairs), otherwise the prefix hint.
pub fn gap_error(promisor: Option<&Promisor>, path: &str) -> Error {
    match promisor {
        Some(p) if !path.is_empty() && p.matches(path) => match p.blob_limit() {
            Some(limit) => Error::GapBySize {
                path: path.to_string(),
                limit,
            },
            None => partial_gap_hint(path),
        },
        _ => partial_gap_hint(path),
    }
}

/// Build the "this operation isn't supported on a partial clone at all"
/// error (P27 Task 5 review fix): merge, cherry-pick/rebase replay, `sc ws
/// harvest`, and `sc work` all need the FULL tree of whatever they touch,
/// not just one path — `partial_gap_hint`'s `sc backfill <path>` phrasing
/// was misleading there (there's no single path to name), and feeding it a
/// free-text sentence in place of a path produced a garbled, non-actionable
/// message (`sc backfill <merge across this partial clone's fetch
/// filter>`). `op` is a short operation name, e.g. `"merge"`.
pub fn partial_clone_unsupported(op: &str) -> Error {
    Error::PartialCloneUnsupported(op.to_string())
}

/// Load the repo's promisor marker. An absent `.sc/promisor` file reads as
/// `None` — a full clone, not an empty filter. `.sc/promisor-blob-limit`
/// (ADR-0055) is read only when `.sc/promisor` exists: a stray limit file
/// without it is leftover state and is ignored.
pub fn load(layout: &Layout) -> Result<Option<Promisor>> {
    match std::fs::read_to_string(layout.promisor_path()) {
        Ok(text) => {
            let mut lines = text.lines();
            let origin = match lines.next() {
                Some(line) => line
                    .strip_prefix("origin ")
                    .ok_or_else(|| {
                        Error::InvalidArgument(
                            "malformed .sc/promisor: first line must be 'origin <url>'".into(),
                        )
                    })?
                    .to_string(),
                None => {
                    return Err(Error::InvalidArgument(
                        "malformed .sc/promisor: missing 'origin <url>' line".into(),
                    ))
                }
            };
            let prefixes: Vec<String> = lines.map(|l| l.to_string()).collect();
            let (blob_limit, all_paths) = load_limit(layout)?;
            let scope = if all_paths {
                Scope::AllPaths
            } else {
                Scope::Prefixes(prefixes)
            };
            Ok(Some(Promisor {
                scope,
                blob_limit,
                origin,
            }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Parse `.sc/promisor-blob-limit`: `limit <bytes>` then `scope all-paths` or
/// `scope prefixes`. Absent file = no limit and prefix scope.
fn load_limit(layout: &Layout) -> Result<(Option<u64>, bool)> {
    let text = match std::fs::read_to_string(layout.promisor_blob_limit_path()) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((None, false)),
        Err(e) => return Err(e.into()),
    };
    let bad = || {
        Error::InvalidArgument(
            "malformed .sc/promisor-blob-limit: expected 'limit <bytes>' then \
             'scope all-paths|prefixes'"
                .into(),
        )
    };
    let mut lines = text.lines();
    let limit = lines
        .next()
        .and_then(|l| l.strip_prefix("limit "))
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or_else(bad)?;
    let all_paths = match lines.next() {
        Some("scope all-paths") => true,
        Some("scope prefixes") => false,
        _ => return Err(bad()),
    };
    Ok((Some(limit), all_paths))
}

/// Persist the repo's promisor marker, atomically. The limit file goes first:
/// a crash between the two writes leaves a limit file with no marker (ignored
/// by [`load`]) rather than a marker that has lost its limit.
pub fn store(layout: &Layout, p: &Promisor) -> Result<()> {
    match p.blob_limit {
        Some(limit) => {
            let scope = if p.is_all_paths() {
                "all-paths"
            } else {
                "prefixes"
            };
            let text = format!("limit {limit}\nscope {scope}\n");
            scl_core::fsutil::atomic_write_durable(
                &layout.promisor_blob_limit_path(),
                text.as_bytes(),
            )?;
        }
        None => remove_file_if_exists(&layout.promisor_blob_limit_path())?,
    }
    let mut text = format!("origin {}\n", p.origin);
    for prefix in p.prefixes() {
        text.push_str(prefix);
        text.push('\n');
    }
    scl_core::fsutil::atomic_write_durable(&layout.promisor_path(), text.as_bytes())?;
    Ok(())
}

fn remove_file_if_exists(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Remove the repo's promisor marker: this repo becomes a genuine full
/// clone (P27 final review I2, `Repo::backfill_all`'s escape hatch). A
/// no-op if the marker is already absent. Callers MUST only call this
/// after independently confirming the object closure is actually
/// complete — this function does not itself verify anything.
pub fn remove(layout: &Layout) -> Result<()> {
    set_lazy(layout, false)?;
    remove_file_if_exists(&layout.promisor_blob_limit_path())?;
    remove_file_if_exists(&layout.promisor_path())
}

/// True when this partial clone has opted in to filling gaps by object id
/// (ADR-0047). Absent marker, or no promisor at all, reads as `false`.
pub fn is_lazy(layout: &Layout) -> bool {
    layout.promisor_lazy_path().is_file()
}

/// Set or clear the lazy marker. Clearing an absent marker is a no-op.
pub fn set_lazy(layout: &Layout, lazy: bool) -> Result<()> {
    if lazy {
        scl_core::fsutil::atomic_write_durable(&layout.promisor_lazy_path(), b"")?;
        return Ok(());
    }
    match std::fs::remove_file(layout.promisor_lazy_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// True when the environment forces offline behavior (`SC_OFFLINE` set to
/// anything but empty or `0`): a lazy clone then reports the gap error
/// instead of dialing the promisor remote.
pub fn offline() -> bool {
    matches!(std::env::var("SC_OFFLINE"), Ok(v) if !v.is_empty() && v != "0")
}

impl Repo {
    /// Refuse `op` on a partial clone with the explicit
    /// [`Error::PartialCloneUnsupported`] message. For commands that flatten
    /// whole trees and would otherwise fail with a raw `NotFound` on the
    /// first absent object (ADR-0048).
    pub(crate) fn refuse_on_partial(&self, op: &str) -> Result<()> {
        if self.promisor()?.is_some() {
            return Err(partial_clone_unsupported(op));
        }
        Ok(())
    }

    /// The repo's current promisor marker, if any (thin wrapper over
    /// `load`). `None` means this is a full clone.
    pub fn promisor(&self) -> Result<Option<Promisor>> {
        load(self.layout())
    }

    /// The gap count for `sc verify`'s partial-clone report (ADR-0048): the
    /// number of objects a present tree references that the store lacks,
    /// from the presence-based walk over `tips`. `None` if this is a full
    /// clone (no `.sc/promisor`). A gap is expected on a partial clone, never
    /// treated as corruption, and the count is the size of the gap frontier:
    /// a fill can replace one missing tree with several missing children, so
    /// it is not a measure of progress.
    pub fn partial_gap_count(&self, tips: &[scl_core::ObjectId]) -> Result<Option<usize>> {
        if self.promisor()?.is_none() {
            return Ok(None);
        }
        let store_arc = self.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let r = crate::reachable::reachable_objects_partial(&mut store, tips)?;
        Ok(Some(r.gaps.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_layout(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-promisor-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        layout
    }

    #[test]
    fn matches_boundary() {
        let p = Promisor::new("origin-url", vec!["src/".into()]);
        assert!(p.matches("src/a"));
        assert!(p.matches("src"));
        assert!(!p.matches("srcfoo"));
        assert!(!p.matches("docs/x"));
    }

    #[test]
    fn should_descend_includes_ancestors() {
        let p = Promisor::new("origin-url", vec!["src/app/".into()]);
        // "src" is an ancestor of the in-filter "src/app/" — must descend
        // through it to reach the filtered content, but "src" itself is not
        // in-filter.
        assert!(p.should_descend("src"));
        assert!(!p.matches("src"));
        // "src/app" is itself in-filter.
        assert!(p.should_descend("src/app"));
        assert!(p.matches("src/app"));
        // Unrelated subtree: neither in-filter nor an ancestor.
        assert!(!p.should_descend("docs"));
        assert!(!p.matches("docs"));
        // The root always descends.
        assert!(p.should_descend(""));
    }

    #[test]
    fn store_load_round_trip() {
        let layout = tmp_layout("rt");
        // Absent file reads as None (a full clone).
        assert_eq!(load(&layout).unwrap(), None);

        let p = Promisor::new("ssh://host/repo", vec!["src/".into(), "docs/".into()]);
        store(&layout, &p).unwrap();
        assert_eq!(load(&layout).unwrap(), Some(p));

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn widen_dedups() {
        let mut p = Promisor::new("origin-url", vec!["src/".into()]);
        p.widen(&["docs/".into(), "src/".into(), "tests/".into()]);
        assert_eq!(
            p.prefixes(),
            &[
                "src/".to_string(),
                "docs/".to_string(),
                "tests/".to_string()
            ]
        );

        // Widening with an already-present set is a no-op.
        p.widen(&["src/".into(), "docs/".into(), "tests/".into()]);
        assert_eq!(p.prefixes().len(), 3);
    }

    #[test]
    fn lazy_marker_is_separate_from_the_filter_file() {
        let layout = tmp_layout("lazy");
        // A prefix that looks like a config line must stay a plain prefix:
        // laziness lives in its own marker, never in `.sc/promisor`.
        let p = Promisor::new("origin-url", vec!["lazy = true".into()]);
        store(&layout, &p).unwrap();
        assert!(!is_lazy(&layout));
        assert_eq!(load(&layout).unwrap(), Some(p.clone()));

        set_lazy(&layout, true).unwrap();
        assert!(is_lazy(&layout));
        assert_eq!(load(&layout).unwrap(), Some(p));

        set_lazy(&layout, false).unwrap();
        assert!(!is_lazy(&layout));
        // Clearing an absent marker is a no-op.
        set_lazy(&layout, false).unwrap();

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn remove_clears_the_lazy_marker_too() {
        let layout = tmp_layout("lazy-rm");
        store(&layout, &Promisor::new("origin-url", vec!["src/".into()])).unwrap();
        set_lazy(&layout, true).unwrap();
        remove(&layout).unwrap();
        assert!(!is_lazy(&layout));
        assert!(!layout.promisor_lazy_path().exists());
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
