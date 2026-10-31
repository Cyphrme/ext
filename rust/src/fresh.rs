//! Pure freshness predicates: racy window, skip decision, status classification.

use crate::digest::Digest;
use crate::index::{Entry, Meta};

pub const RACY_WINDOW_NS: i64 = 2_000_000_000;

/// `meta` and `last_checked_ns` are the values stored with the entry.
///
/// A timestamp inside the window (or in the future, after a clock step) could
/// still be shared by a later edit, so the metadata cannot vouch for content.
pub fn is_racy(meta: &Meta, last_checked_ns: i64) -> bool {
    // Saturating: stored values are untrusted index contents.
    meta.mtime_ns.max(meta.ctime_ns) >= last_checked_ns.saturating_sub(RACY_WINDOW_NS)
}

/// Which metadata fields must match for a file to count as unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaCmp {
    Full,
    /// Size and mtime only, for filesystems whose ctime, inode and device
    /// numbers are unstable (some FUSE and network filesystems). The device
    /// goes with the inode, which is only meaningful beside it.
    SizeMtime,
}

impl MetaCmp {
    fn same(self, a: &Meta, b: &Meta) -> bool {
        match self {
            MetaCmp::Full => a == b,
            MetaCmp::SizeMtime => (a.size, a.mtime_ns) == (b.size, b.mtime_ns),
        }
    }
}

pub fn should_skip(stored: Option<&Entry>, current: &Meta, full: bool, cmp: MetaCmp) -> bool {
    match stored {
        Some(e) if !full => cmp.same(&e.meta, current) && !is_racy(&e.meta, e.last_checked_ns),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    New,
    Edited,
    Unchanged,
    Violation,
}

pub fn classify(stored: Option<&Entry>, current: &Meta, digest: &Digest, cmp: MetaCmp) -> Status {
    let Some(e) = stored else {
        return Status::New;
    };
    if e.digest == *digest {
        Status::Unchanged
    } else if cmp.same(&e.meta, current) && !is_racy(&e.meta, e.last_checked_ns) {
        // Nothing observable changed and the metadata is trustworthy, so
        // the content change is not an ordinary edit.
        Status::Violation
    } else {
        Status::Edited
    }
}
