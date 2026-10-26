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
    // The later of mtime/ctime decides: a restored (old) mtime must not
    // hide a fresh ctime (T1's mechanism, stated purely).
    assert!(is_racy(&meta(1, lc - 10 * W, lc, 1, 1), lc));
    assert!(is_racy(&meta(1, lc, lc - 10 * W, 1, 1), lc));
    assert!(!is_racy(&meta(1, lc - 10 * W, lc - 10 * W, 1, 1), lc));
    // Timestamps from the future (clock stepped back) are racy, never trusted.
    assert!(is_racy(&meta(1, lc + 5 * W, 0, 1, 1), lc));
}

proptest! {
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
}

// Skip only when the stored metadata equals the current, is not racy, and
// the run is not --full. Literal rows, no oracle.
#[test]
fn should_skip_table() {
    let settled = meta(7, T - 100 * W, T - 100 * W, 1, 2);
    let racy = meta(7, T - W / 2, T - 100 * W, 1, 2);
    let rows: &[(&str, Option<Entry>, Meta, bool, bool)] = &[
        (
            "settled and equal",
            Some(entry(settled, T, b"x")),
            settled,
            false,
            true,
        ),
        ("racy", Some(entry(racy, T, b"x")), racy, false, false),
        (
            "--full",
            Some(entry(settled, T, b"x")),
            settled,
            true,
            false,
        ),
        ("no entry", None, settled, false, false),
        (
            "field differs",
            Some(entry(settled, T, b"x")),
            meta(8, T - 100 * W, T - 100 * W, 1, 2),
            false,
            false,
        ),
    ];
    for (name, stored, current, full, want) in rows {
        assert_eq!(
            should_skip(stored.as_ref(), current, *full),
            *want,
            "{name}"
        );
    }
}

// The D1 status table. A violation is a content change with nothing
// observable having changed, on metadata that is trustworthy.
#[test]
fn classify_table() {
    let old = meta(3, T - 100 * W, T - 100 * W, 1, 1);
    let moved = meta(4, T - 100 * W, T - 100 * W, 1, 1);
    let dg = |c: &[u8]| Digest::compute(Alg::Sha256, c);
    let settled = entry(old, T, b"old");
    let racy = entry(old, T - 100 * W + 1, b"old");
    let rows: &[(&str, Option<&Entry>, Meta, Digest, Status)] = &[
        ("no entry", None, old, dg(b"x"), Status::New),
        (
            "same digest, same meta",
            Some(&settled),
            old,
            dg(b"old"),
            Status::Unchanged,
        ),
        (
            "same digest, new meta",
            Some(&settled),
            moved,
            dg(b"old"),
            Status::Unchanged,
        ),
        (
            "same digest, racy",
            Some(&racy),
            old,
            dg(b"old"),
            Status::Unchanged,
        ),
        (
            "new digest, same meta, settled",
            Some(&settled),
            old,
            dg(b"new"),
            Status::Violation,
        ),
        (
            "new digest, same meta, racy",
            Some(&racy),
            old,
            dg(b"new"),
            Status::Edited,
        ),
        (
            "new digest, new meta",
            Some(&settled),
            moved,
            dg(b"new"),
            Status::Edited,
        ),
    ];
    for (name, stored, cur, digest, want) in rows {
        assert_eq!(classify(*stored, cur, digest), *want, "{name}");
    }
}
