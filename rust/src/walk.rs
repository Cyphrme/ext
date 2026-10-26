//! fd-relative tree walk that never follows symlinks or opens specials.

use crate::index::Meta;
use crate::registry::RegPath;
use std::fs::File;
use std::io;

#[derive(Debug)]
pub enum Event {
    File {
        path: Vec<u8>,
        file: File,
        meta: Meta,
        last_checked_ns: i64,
    },
    Symlink(Vec<u8>),
    Special(Vec<u8>),
    Mount(Vec<u8>),
    SubExtant(Vec<u8>),
    Refused(Vec<u8>, io::Error),
    Error(Vec<u8>, io::Error),
}

pub fn walk(_root: &RegPath, _store_id: (u64, u64), _visit: &mut dyn FnMut(Event)) {
    todo!("step 3")
}

/// Pure so the mount rule is testable without privilege.
pub fn crosses_mount(_root_mnt: u64, _child_mnt: u64) -> bool {
    todo!("step 3")
}
