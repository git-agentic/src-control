//! The first-sighting record: compaction's age source on a Git carrier
//! (ADR-0057 addendum, ADR-0060).
//!
//! A Git host reports no usable object age: the only time is a commit's
//! committer date, which the writer chooses and which predates publication. So
//! on a carrier the compactor keeps its own clock. Bucket key
//! `compact/sightings` (ref `refs/sc/compact/sightings`) holds one line per
//! tracked key, `<first_seen_unix_secs> <oid> <key>\n`, sorted by key, where
//! `oid` is the value's tag (a Git object id) when the compactor first listed it
//! and `first_seen` is the compactor's own clock then. A key whose listed oid
//! differs from the recorded one is a new generation (a deleted key that was
//! uploaded again) and starts its age over. Only `packs/` and `checkpoints/`
//! keys are tracked: log entries are deleted by sequence behind the cutoff,
//! never by age.
//!
//! The record supplies ages and nothing else: it never names something to
//! delete. Anyone who can push can write it, and so can already delete the
//! store directly, so it adds no authority; a malformed or future-dated record
//! is refused, never read as "everything is old".

use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::fmt::Display;

/// Bucket key of the record.
pub(super) const KEY: &str = "compact/sightings";

/// How far past the reader's own clock a recorded first-seen time may lie
/// before the record is refused: compactors that share it must keep clocks
/// within far less than the grace window of each other.
const MAX_FUTURE_SECS: u64 = 5 * 60;

/// Largest record read or written: the metadata cap of every non-pack value.
const MAX_BYTES: usize = scl_core::DEFAULT_MAX_OBJECT_SIZE;

/// First sightings by key: `(first_seen_unix_secs, oid)`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Sightings {
    seen: BTreeMap<String, (u64, String)>,
}

/// An unusable record. It blocks compaction (nothing is deleted on a guess),
/// and the message names the way out.
fn unusable(why: impl Display) -> Error {
    Error::Wal(format!(
        "the compaction age record refs/sc/{KEY} is unusable ({why}); delete that ref on the \
         Git host and rerun (every object's age then starts over)"
    ))
}

/// Whether `key` is one the record may name: a `packs/` or `checkpoints/` key
/// that the Git carrier itself would accept (its ref-safe charset and shape;
/// a listed key always passes, so a record this module wrote always decodes).
fn tracked(key: &str) -> bool {
    (key.starts_with("packs/") || key.starts_with("checkpoints/"))
        && key.len() <= 1024
        && !key.contains("..")
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
        && key.split('/').all(|c| {
            !c.is_empty() && !c.starts_with('.') && !c.ends_with('.') && !c.ends_with(".lock")
        })
}

/// A full lowercase hex object id (40 digits).
fn is_oid(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Sightings {
    /// Strict canonical decode of a record read at `now` (the reader's clock,
    /// unix seconds). Anything outside the canonical form is an error: plain
    /// decimal seconds, a 40-digit lowercase oid, a tracked key, keys sorted and
    /// unique, a final newline, and no first-seen time more than five minutes
    /// ahead of `now` (compactor clocks disagree).
    pub(super) fn decode(bytes: &[u8], now: u64) -> Result<Sightings> {
        let text = std::str::from_utf8(bytes).map_err(|_| unusable("not UTF-8"))?;
        let mut seen = BTreeMap::new();
        if text.is_empty() {
            return Ok(Sightings { seen });
        }
        let body = text
            .strip_suffix('\n')
            .ok_or_else(|| unusable("no final newline"))?;
        let mut prev: Option<&str> = None;
        for (i, line) in body.split('\n').enumerate() {
            let at = |why: &str| unusable(format!("line {}: {why}", i + 1));
            let mut f = line.splitn(3, ' ');
            let (Some(secs), Some(oid), Some(key)) = (f.next(), f.next(), f.next()) else {
                return Err(at("expected `<secs> <oid> <key>`"));
            };
            let first_seen: u64 = secs.parse().map_err(|_| at("bad seconds"))?;
            if first_seen.to_string() != secs {
                return Err(at("seconds are not plain decimal"));
            }
            if !is_oid(oid) {
                return Err(at("oid is not 40 lowercase hex digits"));
            }
            if !tracked(key) {
                return Err(at("key is not a tracked packs/ or checkpoints/ key"));
            }
            if prev.is_some_and(|p| p >= key) {
                return Err(at("keys are not sorted and unique"));
            }
            if first_seen > now.saturating_add(MAX_FUTURE_SECS) {
                return Err(Error::Wal(format!(
                    "compactor clocks disagree: the age record refs/sc/{KEY} has a first sighting \
                     at {first_seen}, more than five minutes after this clock ({now}). Run \
                     compaction from one host, or fix the clocks; to discard the record, delete \
                     that ref on the Git host"
                )));
            }
            prev = Some(key);
            seen.insert(key.to_string(), (first_seen, oid.to_string()));
        }
        Ok(Sightings { seen })
    }

    /// Canonical bytes, or an error when the record would pass the size cap
    /// (it is never truncated: dropping entries would reset ages).
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        self.encode_within(MAX_BYTES)
    }

    fn encode_within(&self, max: usize) -> Result<Vec<u8>> {
        let mut out = String::new();
        for (key, (first_seen, oid)) in &self.seen {
            out.push_str(&format!("{first_seen} {oid} {key}\n"));
            if out.len() > max {
                return Err(Error::Wal(format!(
                    "the compaction age record would exceed {max} bytes ({} tracked keys)",
                    self.seen.len()
                )));
            }
        }
        Ok(out.into_bytes())
    }

    /// The record after this listing, taken at `now`: a tracked listed key keeps
    /// its first-seen time while its oid is the recorded one, and starts at
    /// `now` when it is unrecorded or holds a different oid; a key no longer
    /// listed is dropped. Untracked keys are ignored.
    pub(super) fn observe(&self, listed: &[(String, String)], now: u64) -> Sightings {
        let seen = listed
            .iter()
            .filter(|(key, _)| tracked(key))
            .map(|(key, oid)| {
                let first_seen = match self.seen.get(key) {
                    Some((t, recorded)) if recorded == oid => *t,
                    _ => now,
                };
                (key.clone(), (first_seen, oid.clone()))
            })
            .collect();
        Sightings { seen }
    }

    /// When `key` was first seen, if it is recorded.
    pub(super) fn first_seen(&self, key: &str) -> Option<u64> {
        self.seen.get(key).map(|(t, _)| *t)
    }

    /// The recorded keys, sorted (for tests).
    #[cfg(test)]
    pub(super) fn keys(&self) -> Vec<&str> {
        self.seen.keys().map(String::as_str).collect()
    }

    /// How many keys are recorded here that `before` does not hold at the same
    /// oid: the sightings a run adds.
    pub(super) fn added_since(&self, before: &Sightings) -> usize {
        self.seen
            .iter()
            .filter(|(k, v)| before.seen.get(*k) != Some(*v))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn rec(lines: &[(&str, u64, &str)]) -> Sightings {
        Sightings {
            seen: lines
                .iter()
                .map(|(k, t, o)| (k.to_string(), (*t, o.to_string())))
                .collect(),
        }
    }

    #[test]
    fn a_record_round_trips_in_one_canonical_form() {
        let r = rec(&[
            ("checkpoints/00000000000000000065", 10, A),
            ("packs/ab12.idx", 20, B),
            ("packs/ab12.pack", 0, A),
        ]);
        let bytes = r.encode().unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            format!(
                "10 {A} checkpoints/00000000000000000065\n20 {B} packs/ab12.idx\n0 {A} packs/ab12.pack\n"
            )
        );
        assert_eq!(Sightings::decode(&bytes, 100).unwrap(), r);
        assert_eq!(Sightings::decode(b"", 100).unwrap(), Sightings::default());
        assert!(Sightings::default().encode().unwrap().is_empty());
    }

    #[test]
    fn anything_but_the_canonical_form_is_an_error_that_names_the_fix() {
        let ok = format!("5 {A} packs/x.pack\n");
        Sightings::decode(ok.as_bytes(), 100).unwrap();
        let upper = A.to_uppercase();
        let short = &A[..39];
        let long = format!("{A}a");
        let bad: Vec<(String, &str)> = vec![
            (format!("5 {A} packs/x.pack"), "no final newline"),
            (format!("5 {A} packs/x.pack\n\n"), "blank line"),
            (format!("05 {A} packs/x.pack\n"), "leading zero"),
            (format!("+5 {A} packs/x.pack\n"), "plus sign"),
            (format!("-5 {A} packs/x.pack\n"), "negative"),
            (format!("5.0 {A} packs/x.pack\n"), "fraction"),
            (format!(" 5 {A} packs/x.pack\n"), "space"),
            (
                format!("99999999999999999999999 {A} packs/x.pack\n"),
                "overflow",
            ),
            (format!("5 {upper} packs/x.pack\n"), "uppercase oid"),
            (format!("5 {short} packs/x.pack\n"), "short oid"),
            (format!("5 {long} packs/x.pack\n"), "long oid"),
            ("5 zz packs/x.pack\n".to_string(), "non-hex oid"),
            (format!("5 {A}\n"), "no key"),
            (format!("5 {A} manifest\n"), "manifest is not tracked"),
            (
                format!("5 {A} log/00000000000000000001\n"),
                "logs are not tracked",
            ),
            (
                format!("5 {A} compact/sightings\n"),
                "the record is not tracked",
            ),
            (format!("5 {A} packs/../x\n"), "dotdot"),
            (format!("5 {A} packs/a b\n"), "space in key"),
            (format!("5 {A} packs/.x\n"), "hidden"),
            (format!("5 {A} packs/x.lock\n"), "lock suffix"),
            (format!("5 {A} packs//x\n"), "empty component"),
            (format!("5 {A} packs/é\n"), "non-ascii key"),
            (
                format!("5 {A} packs/b.pack\n5 {A} packs/a.pack\n"),
                "unsorted",
            ),
            (
                format!("5 {A} packs/a.pack\n6 {B} packs/a.pack\n"),
                "duplicate",
            ),
            (format!("5 {A} packs/x.pack\r\n"), "crlf"),
        ];
        for (text, why) in &bad {
            let e = Sightings::decode(text.as_bytes(), 100)
                .expect_err(why)
                .to_string();
            assert!(
                e.contains("unusable") && e.contains("delete that ref"),
                "{why}: {e}"
            );
        }
        let e = Sightings::decode(&[0xff, 0xfe], 100)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not UTF-8"), "{e}");
    }

    #[test]
    fn a_first_sighting_in_the_future_is_refused_beyond_five_minutes() {
        let at = |t: u64| format!("{t} {A} packs/x.pack\n");
        // within the allowance (a compactor whose clock runs a little ahead)
        Sightings::decode(at(100 + MAX_FUTURE_SECS).as_bytes(), 100).unwrap();
        let e = Sightings::decode(at(100 + MAX_FUTURE_SECS + 1).as_bytes(), 100)
            .unwrap_err()
            .to_string();
        assert!(e.contains("clocks disagree"), "{e}");
        assert!(e.contains("delete that ref"), "{e}");
    }

    #[test]
    fn observe_keeps_ages_per_generation_and_drops_what_is_gone() {
        let before = rec(&[
            ("packs/a.idx", 10, A),
            ("packs/b.pack", 20, A),
            ("packs/gone.pack", 30, A),
        ]);
        let listed = vec![
            ("log/00000000000000000001".to_string(), A.to_string()),
            ("manifest".to_string(), A.to_string()),
            ("packs/a.idx".to_string(), A.to_string()), // same oid: keeps its age
            ("packs/b.pack".to_string(), B.to_string()), // re-created: a new generation
            ("packs/new.pack".to_string(), B.to_string()), // first sighting
        ];
        let after = before.observe(&listed, 1000);
        assert_eq!(
            after,
            rec(&[
                ("packs/a.idx", 10, A),
                ("packs/b.pack", 1000, B),
                ("packs/new.pack", 1000, B),
            ])
        );
        assert_eq!(after.first_seen("packs/a.idx"), Some(10));
        assert_eq!(after.first_seen("manifest"), None);
        assert_eq!(after.added_since(&before), 2);
        assert_eq!(
            after.observe(&listed, 5000),
            after,
            "unchanged listing is a fixed point"
        );
    }

    #[test]
    fn a_record_past_the_cap_is_an_error_not_a_truncation() {
        let r = rec(&[("packs/a.pack", 1, A), ("packs/b.pack", 2, A)]);
        let full = r.encode().unwrap();
        assert_eq!(r.encode_within(full.len()).unwrap(), full);
        let e = r.encode_within(full.len() - 1).unwrap_err().to_string();
        assert!(e.contains("would exceed"), "{e}");
    }
}
