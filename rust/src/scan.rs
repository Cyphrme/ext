//! Reconcile, walk, hash, classify, and write the index.

use crate::digest::Digest;
use crate::index::Index;
use crate::registry::RegPath;
use crate::store::{Store, StoreError, WriteLock};

#[derive(Clone, Debug, Default)]
pub struct Opts {
    pub full: bool,
    pub accept: bool,
    pub only: Option<RegPath>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportKind {
    New,
    Edited,
    Violation,
    /// A violation taken as the new baseline by `--accept`.
    Accepted,
    Missing,
    Excluded,
    Unstable,
    Error,
    Refused,
    SubExtant,
    Mount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub kind: ReportKind,
    pub path: Vec<u8>,
    /// (stored, actual); `Some` for Edited, Violation and Accepted.
    pub digests: Option<(Digest, Digest)>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub new: u64,
    pub edited: u64,
    /// Hashed, digest equal.
    pub unchanged: u64,
    /// Not hashed: metadata matched and the entry was not racy.
    pub skipped: u64,
    pub violation: u64,
    /// Violations taken by `--accept`; never affects the exit code.
    pub accepted: u64,
    pub missing: u64,
    pub excluded: u64,
    pub unstable: u64,
    pub error: u64,
    pub refused: u64,
    pub subextant: u64,
    pub mount: u64,
    pub symlinks: u64,
    pub special: u64,
}

impl Summary {
    /// 2 for an unaccepted violation, 5 for an incomplete scan, else 0.
    pub fn exit_code(&self) -> i32 {
        todo!("step 3")
    }
}

pub fn run(
    store: &Store,
    lock: &WriteLock,
    idx: &Index,
    opts: &Opts,
    out: &mut dyn FnMut(Report),
) -> Result<Summary, StoreError> {
    run_hooked(store, lock, idx, opts, &mut |_, _| {}, out)
}

/// `after_chunk(path, bytes_so_far)` is forwarded to `hash_stable` so tests
/// can mutate a file mid-hash.
pub fn run_hooked(
    _store: &Store,
    _lock: &WriteLock,
    _idx: &Index,
    _opts: &Opts,
    _after_chunk: &mut dyn FnMut(&[u8], u64),
    _out: &mut dyn FnMut(Report),
) -> Result<Summary, StoreError> {
    todo!("step 3")
}
