//! Plan §4 `fresh.rs`: pure racy/skip/classify predicates with an injected
//! clock. No filesystem, so ctime cannot leak in (A2, T2).

use ext::digest::{Alg, Digest};
use ext::fresh::{classify, is_racy, should_skip, Status, RACY_WINDOW_NS as W};
use ext::index::{Entry, Meta};
use proptest::prelude::*;

fn meta(size: u64, m: i64, c: i64, dev: u64, ino: u64) -> Meta {
    Meta {
        size,
        mtime_ns: m,
        ctime_ns: c,
        dev,
        ino,
    }
}

fn entry(meta: Meta, last_checked_ns: i64, content: &[u8]) -> Entry {
    Entry {
        path: b"/r/f".to_vec(),
        digest: Digest::compute(Alg::Sha256, content),
        meta,
        last_checked_ns,
    }
}

const T: i64 = 1_700_000_000_000_000_000;

// A2 boundary: racy iff max(mtime, ctime) >= last_checked - W, so equality
// is racy and one nanosecond earlier is not.
#[test]
fn racy_boundary_is_inclusive() {
    let lc = T;
    assert!(is_racy(&meta(1, lc - W, 0, 1, 1), lc));
    assert!(!is_racy(&meta(1, lc - W - 1, 0, 1, 1), lc));
    assert!(is_racy(&meta(1, 0, lc - W, 1, 1), lc));
    assert!(!is_racy(&meta(1, 0, lc - W - 1, 1, 1), lc));
}

// Whichever of mtime/ctime is later decides; a restored (old) mtime must not
// hide a fresh ctime (T1's mechanism, stated purely).
#[test]
fn racy_uses_the_later_of_mtime_and_ctime() {
    let lc = T;
    assert!(is_racy(&meta(1, lc - 10 * W, lc, 1, 1), lc));
    assert!(is_racy(&meta(1, lc, lc - 10 * W, 1, 1), lc));
    assert!(!is_racy(&meta(1, lc - 10 * W, lc - 10 * W, 1, 1), lc));
}

// Timestamps from the future (clock stepped back) are racy, never trusted.
#[test]
fn future_timestamps_are_racy() {
    assert!(is_racy(&meta(1, T + 5 * W, 0, 1, 1), T));
}

fn near(lc: i64) -> impl Strategy<Value = i64> {
    prop_oneof![
        (-3i64..=3).prop_map(move |d| lc - W + d),
        (0i64..4 * W).prop_map(move |d| lc - d),
        (-W..W).prop_map(move |d| lc + d),
    ]
}

fn case() -> impl Strategy<Value = (i64, i64, i64)> {
    (3 * W..i64::MAX / 4).prop_flat_map(|lc| (Just(lc), near(lc), near(lc)))
}

proptest! {
    #[test]
    fn racy_matches_oracle((lc, m, c) in case()) {
        prop_assert_eq!(is_racy(&meta(1, m, c, 1, 1), lc), m.max(c) >= lc - W);
    }

    // Equal metadata, not racy, not --full => skip; the whole decision.
    #[test]
    fn skip_iff_equal_and_not_racy_and_not_full(
        size in any::<u64>(), dev in any::<u64>(), ino in any::<u64>(),
        lc in 3 * W..i64::MAX / 2, dm in 0i64..6 * W, dc in 0i64..6 * W, full in any::<bool>(),
    ) {
        let mt = meta(size, lc - dm, lc - dc, dev, ino);
        let e = entry(mt, lc, b"x");
        let racy = (lc - dm).max(lc - dc) >= lc - W;
        prop_assert_eq!(should_skip(Some(&e), &mt, full), !full && !racy);
    }

    // Any single metadata field differing forbids skipping, even when the
    // entry is old enough not to be racy.
    #[test]
    fn any_field_difference_never_skips(
        field in 0usize..5, delta in 1u32..1000,
        size in 0u64..1 << 40, dev in 0u64..1 << 40, ino in 0u64..1 << 40,
    ) {
        let lc = T;
        let base = meta(size, lc - 100 * W, lc - 100 * W, dev, ino);
        let e = entry(base, lc, b"x");
        let d = delta as i64;
        let mut cur = base;
        match field {
            0 => cur.size += delta as u64,
            1 => cur.mtime_ns += d,
            2 => cur.ctime_ns += d,
            3 => cur.dev += delta as u64,
            _ => cur.ino += delta as u64,
        }
        prop_assert!(!should_skip(Some(&e), &cur, false));
        // Control: the unmodified metadata of the same entry does skip, so
        // the assertion above cannot hold merely because skip is always false.
        prop_assert!(should_skip(Some(&e), &base, false));
    }

    // Racy => never skip, however equal the metadata.
    #[test]
    fn racy_never_skips(lc in 3 * W..i64::MAX / 2, within in 0i64..W) {
        let mt = meta(7, lc - within, lc - 5 * W, 1, 2);
        prop_assert!(is_racy(&mt, lc));
        prop_assert!(!should_skip(Some(&entry(mt, lc, b"x")), &mt, false));
    }

    // Convergence: re-hashing at `now` records last_checked = now; once the
    // file's newest timestamp is more than W older than that, it is no longer
    // racy, so a settled file eventually skips.
    #[test]
    fn racy_entry_converges(newest in 0i64..T, gap in (W + 1)..10 * W) {
        let mt = meta(7, newest, newest, 1, 2);
        let now = newest + gap;
        prop_assert!(!is_racy(&mt, now));
        prop_assert!(should_skip(Some(&entry(mt, now, b"x")), &mt, false));
    }

    // Violation <=> metadata equal, not racy, digest differs.
    #[test]
    fn classify_matches_oracle(
        same_meta in any::<bool>(), same_digest in any::<bool>(), racy in any::<bool>(),
    ) {
        let stored_meta = meta(3, T - 100 * W, T - 100 * W, 1, 1);
        let lc = if racy { T - 100 * W + 1 } else { T };
        let e = entry(stored_meta, lc, b"old");
        let cur = if same_meta { stored_meta } else { meta(4, T - 100 * W, T - 100 * W, 1, 1) };
        let dg = Digest::compute(Alg::Sha256, if same_digest { b"old" } else { b"new" });
        let want = if same_digest {
            Status::Unchanged
        } else if same_meta && !racy {
            Status::Violation
        } else {
            Status::Edited
        };
        prop_assert_eq!(classify(Some(&e), &cur, &dg), want);
    }
}

#[test]
fn classify_without_entry_is_new() {
    let m = meta(1, 1, 1, 1, 1);
    assert_eq!(
        classify(None, &m, &Digest::compute(Alg::Sha256, b"x")),
        Status::New
    );
}
