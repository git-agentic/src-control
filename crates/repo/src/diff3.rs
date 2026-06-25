//! Dependency-free line-level three-way merge (diff3-style).
//!
//! `merge_lines(base, ours, theirs)` aligns each side to `base` via an LCS of
//! lines, then reconciles the regions between common anchors: a region changed
//! on only one side is taken; identical changes are taken once; genuinely
//! divergent regions emit `<<<<<<< / ======= / >>>>>>>` markers and flag a
//! conflict. Operates on `\n`-separated lines and preserves a trailing newline.

/// Result of a three-way line merge.
pub struct Merged {
    pub text: String,
    pub conflicted: bool,
}

/// Three-way merge of three text buffers.
pub fn merge_lines(base: &str, ours: &str, theirs: &str) -> Merged {
    let (b, _b_nl) = split_lines(base);
    let (o, o_nl) = split_lines(ours);
    let (t, t_nl) = split_lines(theirs);

    // Build hunks from two independent diffs (base→ours, base→theirs).
    // Each hunk is a range of base indices and the corresponding replacement lines.
    let o_hunks = diff_hunks(&b, &o);
    let t_hunks = diff_hunks(&b, &t);

    // Merge the two hunk lists by scanning base line by line.
    let mut out: Vec<&str> = Vec::new();
    let mut conflicted = false;

    let mut bi = 0usize; // current base index
    let mut oi = 0usize; // index into o_hunks
    let mut ti = 0usize; // index into t_hunks

    while bi <= b.len() {
        let o_hunk = o_hunks.get(oi);
        let t_hunk = t_hunks.get(ti);

        // Find the next hunk start.
        let next_o = o_hunk.map(|h: &Hunk| h.base_start).unwrap_or(usize::MAX);
        let next_t = t_hunk.map(|h: &Hunk| h.base_start).unwrap_or(usize::MAX);

        let next_change = next_o.min(next_t);

        // Emit unchanged base lines up to the next change.
        let emit_until = next_change.min(b.len());
        while bi < emit_until {
            out.push(b[bi]);
            bi += 1;
        }

        if bi >= b.len() && next_change == usize::MAX {
            break;
        }
        if next_change == usize::MAX {
            break;
        }

        // Both hunks start at the same base position → potential conflict.
        if next_o == next_t {
            let oh = o_hunk.unwrap();
            let th = t_hunk.unwrap();

            // Determine the base range covered by either hunk.
            let base_end = oh.base_end.max(th.base_end);

            // Collect all o_hunks and t_hunks that overlap [next_change, base_end).
            let mut o_replacement: Vec<&str> = Vec::new();
            let mut t_replacement: Vec<&str> = Vec::new();
            let mut base_end_combined = base_end;

            let mut oi2 = oi;
            let mut ti2 = ti;

            loop {
                let more_o = o_hunks
                    .get(oi2)
                    .map(|h| h.base_start < base_end_combined)
                    .unwrap_or(false);
                let more_t = t_hunks
                    .get(ti2)
                    .map(|h| h.base_start < base_end_combined)
                    .unwrap_or(false);
                if !more_o && !more_t {
                    break;
                }
                if more_o {
                    let h = &o_hunks[oi2];
                    // Fill gap with base lines.
                    while o_replacement.len() < h.base_start.saturating_sub(bi) {
                        let idx = bi + o_replacement.len();
                        if idx < b.len() {
                            o_replacement.push(b[idx]);
                        }
                    }
                    o_replacement.extend_from_slice(&h.replacement);
                    base_end_combined = base_end_combined.max(h.base_end);
                    oi2 += 1;
                }
                if more_t {
                    let h = &t_hunks[ti2];
                    while t_replacement.len() < h.base_start.saturating_sub(bi) {
                        let idx = bi + t_replacement.len();
                        if idx < b.len() {
                            t_replacement.push(b[idx]);
                        }
                    }
                    t_replacement.extend_from_slice(&h.replacement);
                    base_end_combined = base_end_combined.max(h.base_end);
                    ti2 += 1;
                }
            }

            // Fill remaining base lines (between last hunk end and base_end_combined).
            let o_base_len = base_end_combined - bi;
            let t_base_len = base_end_combined - bi;
            while o_replacement.len() < o_base_len {
                let idx = bi + o_replacement.len();
                if idx < b.len() {
                    o_replacement.push(b[idx]);
                }
            }
            while t_replacement.len() < t_base_len {
                let idx = bi + t_replacement.len();
                if idx < b.len() {
                    t_replacement.push(b[idx]);
                }
            }

            let base_region = &b[bi..base_end_combined.min(b.len())];

            if o_replacement == t_replacement {
                out.extend_from_slice(&o_replacement);
            } else if o_replacement == base_region {
                out.extend_from_slice(&t_replacement);
            } else if t_replacement == base_region {
                out.extend_from_slice(&o_replacement);
            } else {
                conflicted = true;
                out.push("<<<<<<< ours");
                out.extend_from_slice(&o_replacement);
                out.push("=======");
                out.extend_from_slice(&t_replacement);
                out.push(">>>>>>> theirs");
            }

            bi = base_end_combined;
            oi = oi2;
            ti = ti2;
        } else if next_o < next_t {
            // Only ours has a hunk here.
            let oh = o_hunk.unwrap();
            // Emit base lines between bi and oh.base_start (already done above).
            out.extend_from_slice(&oh.replacement);
            bi = oh.base_end;
            oi += 1;
        } else {
            // Only theirs has a hunk here.
            let th = t_hunk.unwrap();
            out.extend_from_slice(&th.replacement);
            bi = th.base_end;
            ti += 1;
        }
    }

    let mut text = out.join("\n");
    // Trailing newline: ours' convention wins, then theirs, then base.
    let trailing = if !o.is_empty() {
        o_nl
    } else if !t.is_empty() {
        t_nl
    } else {
        _b_nl
    };
    if !text.is_empty() && trailing {
        text.push('\n');
    }
    Merged { text, conflicted }
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
}
