//! Minimal unified-diff formatting for `sc diff`.
//!
//! Line-based LCS with 3 lines of context and `@@` hunk headers — enough to
//! read a working-tree change; not a patch-exchange format (no `\ No newline`
//! marker, no rename detection). Inputs larger than the LCS budget degrade to
//! one whole-file replacement hunk rather than an O(n·m) blowup.

/// One line of a diff body.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Op {
    Keep,
    Del,
    Add,
}

const CONTEXT: usize = 3;
/// LCS DP budget: above `old_lines * new_lines > LCS_BUDGET`, emit one
/// replace-everything hunk instead of computing the table.
const LCS_BUDGET: usize = 4_000_000;

/// Unified diff of `old` → `new` under the shared repo-relative `path`
/// (rendered as `a/<path>` and `b/<path>`). Returns `""` when equal.
pub fn unified(path: &str, old: &str, new: &str) -> String {
    if old == new {
        return String::new();
    }
    let o: Vec<&str> = old.lines().collect();
    let n: Vec<&str> = new.lines().collect();
    let script = edit_script(&o, &n);

    let mut out = format!("--- a/{path}\n+++ b/{path}\n");
    // Group ops into hunks separated by > 2*CONTEXT unchanged lines.
    let mut i = 0; // index into script
    let mut oline = 0usize; // 0-based positions consumed
    let mut nline = 0usize;
    while i < script.len() {
        // Skip the unchanged run before the next change.
        while i < script.len() && script[i] == Op::Keep {
            oline += 1;
            nline += 1;
            i += 1;
        }
        if i == script.len() {
            break;
        }
        // Hunk starts CONTEXT lines back.
        let lead = CONTEXT.min(oline.min(nline));
        let (hunk_ostart, hunk_nstart) = (oline - lead, nline - lead);
        let mut body: Vec<String> = (0..lead)
            .map(|k| format!(" {}", o[hunk_ostart + k]))
            .collect();
        let (mut ocount, mut ncount) = (lead, lead);
        // Consume changes and interior context until a gap of > 2*CONTEXT keeps.
        loop {
            while i < script.len() && script[i] != Op::Keep {
                match script[i] {
                    Op::Del => {
                        body.push(format!("-{}", o[oline]));
                        oline += 1;
                        ocount += 1;
                    }
                    Op::Add => {
                        body.push(format!("+{}", n[nline]));
                        nline += 1;
                        ncount += 1;
                    }
                    Op::Keep => unreachable!(),
                }
                i += 1;
            }
            // Count the unchanged run ahead.
            let mut run = 0;
            while i + run < script.len() && script[i + run] == Op::Keep {
                run += 1;
            }
            if i + run < script.len() && run <= 2 * CONTEXT {
                // Change follows soon: keep the whole run as interior context.
                for _ in 0..run {
                    body.push(format!(" {}", o[oline]));
                    oline += 1;
                    nline += 1;
                    ocount += 1;
                    ncount += 1;
                }
                i += run;
            } else {
                // Tail context, then close the hunk.
                let tail = run.min(CONTEXT);
                for _ in 0..tail {
                    body.push(format!(" {}", o[oline]));
                    oline += 1;
                    nline += 1;
                    ocount += 1;
                    ncount += 1;
                }
                i += run; // skip the rest of the unchanged run
                          // Fast-forward line counters over the skipped remainder.
                oline += run - tail;
                nline += run - tail;
                break;
            }
        }
        out.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            hunk_ostart + 1,
            ocount,
            hunk_nstart + 1,
            ncount
        ));
        for l in body {
            out.push_str(&l);
            out.push('\n');
        }
    }
    out
}

/// Line-level edit script from LCS. Falls back to full-replace over budget.
fn edit_script(o: &[&str], n: &[&str]) -> Vec<Op> {
    if o.len().saturating_mul(n.len()) > LCS_BUDGET {
        let mut s = vec![Op::Del; o.len()];
        s.extend(std::iter::repeat_n(Op::Add, n.len()));
        return s;
    }
    // DP table of LCS lengths.
    let (ol, nl) = (o.len(), n.len());
    let mut dp = vec![0u32; (ol + 1) * (nl + 1)];
    let idx = |i: usize, j: usize| i * (nl + 1) + j;
    for i in (0..ol).rev() {
        for j in (0..nl).rev() {
            dp[idx(i, j)] = if o[i] == n[j] {
                dp[idx(i + 1, j + 1)] + 1
            } else {
                dp[idx(i + 1, j)].max(dp[idx(i, j + 1)])
            };
        }
    }
    let mut script = Vec::with_capacity(ol + nl);
    let (mut i, mut j) = (0, 0);
    while i < ol && j < nl {
        if o[i] == n[j] {
            script.push(Op::Keep);
            i += 1;
            j += 1;
        } else if dp[idx(i + 1, j)] >= dp[idx(i, j + 1)] {
            script.push(Op::Del);
            i += 1;
        } else {
            script.push(Op::Add);
            j += 1;
        }
    }
    script.extend(std::iter::repeat_n(Op::Del, ol - i));
    script.extend(std::iter::repeat_n(Op::Add, nl - j));
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_inputs_diff_empty() {
        assert_eq!(unified("f", "a\nb\n", "a\nb\n"), "");
    }

    #[test]
    fn single_change_gets_context_and_header() {
        let old = "1\n2\n3\n4\n5\n6\n7\n8\n9\n";
        let new = "1\n2\n3\n4\nFIVE\n6\n7\n8\n9\n";
        let d = unified("f.txt", old, new);
        assert!(d.starts_with("--- a/f.txt\n+++ b/f.txt\n"), "{d}");
        assert!(d.contains("@@ -2,7 +2,7 @@"), "{d}");
        assert!(d.contains("-5\n+FIVE\n"), "{d}");
        // Only 3 lines of context on each side.
        assert!(!d.contains(" 1\n"), "line 1 is beyond context: {d}");
        assert!(!d.contains(" 9\n"), "line 9 is beyond context: {d}");
    }

    #[test]
    fn distant_changes_become_separate_hunks() {
        let old: String = (1..=30).map(|i| format!("l{i}\n")).collect();
        let new = old.replace("l3\n", "l3x\n").replace("l28\n", "l28x\n");
        let d = unified("f", &old, &new);
        let hunks = d.lines().filter(|l| l.starts_with("@@")).count();
        assert_eq!(hunks, 2, "two hunks: {d}");
    }

    #[test]
    fn pure_add_and_pure_delete() {
        let add = unified("f", "", "a\nb\n");
        assert!(add.contains("+a\n+b\n"), "{add}");
        let del = unified("f", "a\nb\n", "");
        assert!(del.contains("-a\n-b\n"), "{del}");
    }
}
