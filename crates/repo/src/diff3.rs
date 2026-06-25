//! Dependency-free line-level three-way merge (diff3-style).
//!
//! `merge_lines(base, ours, theirs)` independently diffs each side against
//! `base` into maximal replacement hunks (via LCS), then groups interacting
//! hunks from both sides into clusters whose base ranges overlap. Each cluster
//! is reconciled: a region changed on one side only is taken; identical changes
//! on both sides are taken once; genuinely divergent clusters emit
//! `<<<<<<< / ======= / >>>>>>>` markers and flag a conflict. Operates on
//! `\n`-separated lines and preserves a trailing newline.

/// Result of a three-way line merge.
#[derive(Debug)]
pub struct Merged {
    pub text: String,
    pub conflicted: bool,
}

/// Which side a hunk came from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Ours,
    Theirs,
}

/// Three-way merge of three text buffers.
///
/// Uses a unified chunk-list diff3: each side is diffed against `base` into
/// maximal change hunks (replacements and pure insertions), the hunks from both
/// sides are grouped into clusters whose base ranges interact, and each cluster
/// is reconciled independently. Non-interacting edits both apply cleanly;
/// overlapping or coincident edits that differ produce conflict markers.
pub fn merge_lines(base: &str, ours: &str, theirs: &str) -> Merged {
    let (b, b_nl) = split_lines(base);
    let (o, o_nl) = split_lines(ours);
    let (t, t_nl) = split_lines(theirs);

    // Build hunks from two independent diffs (base→ours, base→theirs).
    let o_hunks = diff_hunks(&b, &o);
    let t_hunks = diff_hunks(&b, &t);

    // Combine all hunks into one list tagged by side, then form clusters from
    // hunks whose base ranges interact (across sides).
    let mut all: Vec<(Side, Hunk)> = Vec::new();
    for h in o_hunks {
        all.push((Side::Ours, h));
    }
    for h in t_hunks {
        all.push((Side::Theirs, h));
    }

    let clusters = cluster_hunks(&all);

    let mut out: Vec<&str> = Vec::new();
    let mut conflicted = false;
    let mut bi = 0usize; // next unconsumed base index

    for cluster in &clusters {
        // [lo, hi) is the base window spanned by this cluster's hunks.
        let lo = cluster.iter().map(|&i| all[i].1.base_start).min().unwrap();
        let hi = cluster.iter().map(|&i| all[i].1.base_end).max().unwrap();

        // Copy stable base lines preceding the cluster.
        while bi < lo {
            out.push(b[bi]);
            bi += 1;
        }

        let base_region = &b[lo..hi];
        let ours_text = apply_side(&b, lo, hi, &all, cluster, Side::Ours);
        let theirs_text = apply_side(&b, lo, hi, &all, cluster, Side::Theirs);

        if ours_text == base_region {
            out.extend_from_slice(&theirs_text);
        } else if theirs_text == base_region || ours_text == theirs_text {
            // Only ours changed, or both sides changed identically — take ours.
            out.extend_from_slice(&ours_text);
        } else {
            conflicted = true;
            out.push("<<<<<<< ours");
            out.extend_from_slice(&ours_text);
            out.push("=======");
            out.extend_from_slice(&theirs_text);
            out.push(">>>>>>> theirs");
        }

        bi = hi;
    }

    // Copy any base lines after the last cluster.
    while bi < b.len() {
        out.push(b[bi]);
        bi += 1;
    }

    let mut text = out.join("\n");
    // Trailing newline: ours' convention wins, then theirs, then base.
    let trailing = if !o.is_empty() {
        o_nl
    } else if !t.is_empty() {
        t_nl
    } else {
        b_nl
    };
    if !text.is_empty() && trailing {
        text.push('\n');
    }
    Merged { text, conflicted }
}

/// Reconstruct `base[lo..hi]` with one side's hunks (from `cluster`) applied.
/// A side with no hunk in the cluster contributes `base[lo..hi]` verbatim.
fn apply_side<'a>(
    b: &[&'a str],
    lo: usize,
    hi: usize,
    all: &[(Side, Hunk<'a>)],
    cluster: &[usize],
    side: Side,
) -> Vec<&'a str> {
    // Collect this side's hunks in this cluster, sorted by base_start.
    let mut hunks: Vec<&Hunk<'a>> = cluster
        .iter()
        .filter(|&&i| all[i].0 == side)
        .map(|&i| &all[i].1)
        .collect();
    hunks.sort_by_key(|h| (h.base_start, h.base_end));

    let mut out: Vec<&'a str> = Vec::new();
    let mut cursor = lo;
    for h in hunks {
        // Copy untouched base lines up to this hunk's start.
        while cursor < h.base_start {
            out.push(b[cursor]);
            cursor += 1;
        }
        out.extend_from_slice(&h.replacement);
        cursor = cursor.max(h.base_end);
    }
    // Copy remaining untouched base lines to the window end.
    while cursor < hi {
        out.push(b[cursor]);
        cursor += 1;
    }
    out
}

/// Group hunks into clusters by the connected components of the interaction
/// relation. Returns a list of clusters, each a list of indices into `all`,
/// ordered by the cluster's minimum base_start.
fn cluster_hunks(all: &[(Side, Hunk)]) -> Vec<Vec<usize>> {
    let n = all.len();
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut [usize], x: usize) -> usize {
        let mut r = x;
        while parent[r] != r {
            r = parent[r];
        }
        // Path compression.
        let mut c = x;
        while parent[c] != r {
            let next = parent[c];
            parent[c] = r;
            c = next;
        }
        r
    }

    for i in 0..n {
        for j in (i + 1)..n {
            if all[i].0 != all[j].0 && interacts(&all[i].1, &all[j].1) {
                let ri = find(&mut parent, i);
                let rj = find(&mut parent, j);
                if ri != rj {
                    parent[ri] = rj;
                }
            }
        }
    }

    // Bucket indices by their representative, preserving discovery order.
    let mut groups: std::collections::BTreeMap<usize, Vec<usize>> = std::collections::BTreeMap::new();
    for i in 0..n {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }

    let mut clusters: Vec<Vec<usize>> = groups.into_values().collect();
    // Order clusters by their earliest base position so the walk is left-to-right.
    clusters.sort_by_key(|c| c.iter().map(|&i| all[i].1.base_start).min().unwrap());
    clusters
}

/// Whether two hunks (assumed to be on different sides) interact and so belong
/// in the same cluster. Replacements interact on half-open range overlap; pure
/// insertions cluster with insertions at the same point and with any hunk whose
/// closed base range `[start, end]` contains the insertion point.
fn interacts(a: &Hunk, b: &Hunk) -> bool {
    let a_ins = a.base_start == a.base_end;
    let b_ins = b.base_start == b.base_end;
    match (a_ins, b_ins) {
        // Both pure insertions: cluster only if at the same point.
        (true, true) => a.base_start == b.base_start,
        // a is an insertion at point p; cluster if b's closed range contains p.
        (true, false) => b.base_start <= a.base_start && a.base_start <= b.base_end,
        // b is an insertion at point p; cluster if a's closed range contains p.
        (false, true) => a.base_start <= b.base_start && b.base_start <= a.base_end,
        // Two replacements: half-open range overlap.
        (false, false) => a.base_start < b.base_end && b.base_start < a.base_end,
    }
}

/// A changed region: base lines [base_start, base_end) are replaced by `replacement`.
struct Hunk<'a> {
    base_start: usize,
    base_end: usize,
    replacement: Vec<&'a str>,
}

/// Compute hunks from an LCS-based diff of `base` vs `other`.
/// Returns a list of Hunks (sorted by base_start).
fn diff_hunks<'a>(base: &[&'a str], other: &[&'a str]) -> Vec<Hunk<'a>> {
    let map = match_map(base, other);
    // map[i] = Some(j) means base[i] maps to other[j] in the LCS.
    // Build a mapping: which base indices are "kept" and at which other index.
    // Between kept base indices, there are insertions/deletions.

    let mut hunks = Vec::new();

    // Anchors: (base_idx, other_idx) pairs that are in LCS, plus sentinels.
    let mut anchors: Vec<(isize, isize)> = vec![(-1, -1)];
    for (bi, om) in map.iter().enumerate() {
        if let Some(oi) = om {
            anchors.push((bi as isize, *oi as isize));
        }
    }
    anchors.push((base.len() as isize, other.len() as isize));

    for w in anchors.windows(2) {
        let (pb, po) = w[0];
        let (cb, co) = w[1];
        let base_r = &base[(pb + 1) as usize..cb as usize];
        let other_r = &other[(po + 1) as usize..co as usize];

        if base_r != other_r {
            hunks.push(Hunk {
                base_start: (pb + 1) as usize,
                base_end: cb as usize,
                replacement: other_r.to_vec(),
            });
        }
    }

    hunks
}

/// Split into lines, returning the lines and whether the input ended with `\n`.
fn split_lines(s: &str) -> (Vec<&str>, bool) {
    if s.is_empty() {
        return (Vec::new(), false);
    }
    let trailing = s.ends_with('\n');
    let body = if trailing { &s[..s.len() - 1] } else { s };
    (body.split('\n').collect(), trailing)
}

/// For each `base` line, the index of the `other` line it maps to in an LCS
/// (or `None` if that base line is not in the common subsequence).
fn match_map(base: &[&str], other: &[&str]) -> Vec<Option<usize>> {
    let n = base.len();
    let m = other.len();
    // dp[i][j] = LCS length of base[i..] and other[j..].
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if base[i] == other[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut res = vec![None; n];
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if base[i] == other[j] {
            res[i] = Some(j);
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_overlapping_edits_merge_clean() {
        let base = "a\nb\nc\n";
        let ours = "a\nB\nc\n"; // changed line 2
        let theirs = "a\nb\nC\n"; // changed line 3
        let m = merge_lines(base, ours, theirs);
        assert!(!m.conflicted);
        assert_eq!(m.text, "a\nB\nC\n");
    }

    #[test]
    fn overlapping_edits_conflict() {
        let base = "a\nb\nc\n";
        let ours = "a\nX\nc\n";
        let theirs = "a\nY\nc\n";
        let m = merge_lines(base, ours, theirs);
        assert!(m.conflicted);
        assert!(m.text.contains("<<<<<<< ours"));
        assert!(m.text.contains("X"));
        assert!(m.text.contains("======="));
        assert!(m.text.contains("Y"));
        assert!(m.text.contains(">>>>>>> theirs"));
    }

    #[test]
    fn identical_change_on_both_sides_is_clean() {
        let base = "a\nb\n";
        let ours = "a\nB\n";
        let theirs = "a\nB\n";
        let m = merge_lines(base, ours, theirs);
        assert!(!m.conflicted);
        assert_eq!(m.text, "a\nB\n");
    }

    #[test]
    fn one_side_appends_other_unchanged() {
        let base = "a\n";
        let ours = "a\nb\n"; // appended
        let theirs = "a\n"; // unchanged
        let m = merge_lines(base, ours, theirs);
        assert!(!m.conflicted);
        assert_eq!(m.text, "a\nb\n");
    }

    #[test]
    fn missing_trailing_newline_preserved() {
        let base = "a\nb";
        let ours = "a\nB";
        let theirs = "a\nb";
        let m = merge_lines(base, ours, theirs);
        assert!(!m.conflicted);
        assert_eq!(m.text, "a\nB");
    }

    #[test]
    fn overlapping_offset_hunks_conflict() {
        // Bug #1: overlapping-but-offset hunks must conflict, not silently
        // produce "a\nX\nY\nC\n".
        let base = "a\nb\nc\n";
        let ours = "a\nX\nY\n";
        let theirs = "a\nb\nC\n";
        let m = merge_lines(base, ours, theirs);
        assert!(m.conflicted);
        assert!(m.text.contains("<<<<<<< ours"));
        assert_ne!(m.text, "a\nX\nY\nC\n");
    }

    #[test]
    fn both_insert_into_empty_base_conflict() {
        // Bug #2: pure insertions into an empty base must conflict with both
        // adds present, not drop a side.
        let base = "";
        let ours = "a\n";
        let theirs = "b\n";
        let m = merge_lines(base, ours, theirs);
        assert!(m.conflicted);
        assert!(m.text.contains('a'));
        assert!(m.text.contains('b'));
        assert!(m.text.contains("<<<<<<< ours"));
        assert!(m.text.contains(">>>>>>> theirs"));
    }

    #[test]
    fn both_append_at_eof_conflict() {
        // Bug #2: appends at EOF must conflict with both adds present.
        let base = "a\n";
        let ours = "a\nX\n";
        let theirs = "a\nY\n";
        let m = merge_lines(base, ours, theirs);
        assert!(m.conflicted);
        assert!(m.text.contains('X'));
        assert!(m.text.contains('Y'));
    }

    #[test]
    fn both_delete_same_lines_clean() {
        let base = "a\nb\nc\n";
        let ours = "a\nc\n";
        let theirs = "a\nc\n";
        let m = merge_lines(base, ours, theirs);
        assert!(!m.conflicted);
        assert_eq!(m.text, "a\nc\n");
    }

    #[test]
    fn delete_modify_conflict() {
        let base = "a\nb\nc\n";
        let ours = "a\nc\n"; // deletes b
        let theirs = "a\nB\nc\n"; // modifies b
        let m = merge_lines(base, ours, theirs);
        assert!(m.conflicted);
    }

    #[test]
    fn both_insert_identical_clean() {
        let base = "a\n";
        let ours = "a\nZ\n";
        let theirs = "a\nZ\n";
        let m = merge_lines(base, ours, theirs);
        assert!(!m.conflicted);
        assert_eq!(m.text, "a\nZ\n");
    }

    #[test]
    fn repeated_identical_lines_no_panic() {
        let base = "x\nx\nx\n";
        let ours = "x\nx\nx\nx\n";
        let theirs = "x\nx\n";
        let m = merge_lines(base, ours, theirs);
        // Must not panic; just assert it returns a value.
        let _ = m.conflicted;
        let _ = m.text;
    }
}
