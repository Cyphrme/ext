//! SQLite index of path -> digest plus freshness metadata.

use crate::digest::Digest;
use crate::registry::RegPath;
use crate::store::{Store, StoreError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub dev: u64,
    pub ino: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: Vec<u8>,
    pub digest: Digest,
    pub meta: Meta,
    pub last_checked_ns: i64,
}

pub struct Index {
    _private: (),
}

impl Index {
    pub fn open(_store: &Store) -> Result<Index, StoreError> {
        todo!("step 2: open, create schema, user_version")
    }

    pub fn get(&self, _path: &[u8]) -> Result<Option<Entry>, StoreError> {
        todo!("step 2")
    }

    pub fn by_digest(&self, _digest: &Digest) -> Result<Vec<Vec<u8>>, StoreError> {
        todo!("step 2")
    }

    pub fn upsert(&self, _entry: &Entry) -> Result<(), StoreError> {
        todo!("step 2")
    }

    pub fn remove(&self, _path: &[u8]) -> Result<(), StoreError> {
        todo!("step 2")
    }

    pub fn remove_under(&self, _root: &RegPath) -> Result<(), StoreError> {
        todo!("step 2")
    }

    pub fn paths_under(&self, _root: &RegPath) -> Result<Vec<Vec<u8>>, StoreError> {
        todo!("step 2")
    }

    pub fn iter(&self) -> Result<Vec<Entry>, StoreError> {
        todo!("step 2")
    }

    /// Drops every entry not under one of `roots` (registry is authoritative).
    pub fn reconcile(&self, _roots: &[RegPath]) -> Result<(), StoreError> {
        todo!("step 2")
    }
}
