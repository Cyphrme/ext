//! Pure freshness predicates: racy window, skip decision, status classification.

use crate::digest::Digest;
use crate::index::{Entry, Meta};

pub const RACY_WINDOW_NS: i64 = 2_000_000_000;

/// `meta` and `last_checked_ns` are the values stored with the entry.
pub fn is_racy(_meta: &Meta, _last_checked_ns: i64) -> bool {
    todo!("step 3: racy iff max(mtime, ctime) >= last_checked - RACY_WINDOW_NS")
}

pub fn should_skip(_stored: Option<&Entry>, _current: &Meta, _full: bool) -> bool {
    todo!("step 3: skip iff !full, stored, all five fields equal, not racy")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    New,
    Edited,
    Unchanged,
    Violation,
}

pub fn classify(_stored: Option<&Entry>, _current: &Meta, _digest: &Digest) -> Status {
    todo!("step 3")
}
