//! The blob cache (ES-8, ES-10, ES-24 to ES-27, ES-30): records in the
//! `cache` table of `index.db`, files under `<store>/cache/<ALG>/<HEX>`.
//!
//! Contract skeleton: signatures only. Every effect of admit, evict, sweep and
//! the services-file write goes through a [`StepExecutor`], so a test executor
//! can drop effect k and every later one and model a killed process.

use crate::digest::Digest;
use crate::services::Fetchable;
use crate::store::{Store, WriteLock};
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::time::SystemTime;

/// Nanoseconds since the epoch; the CLI passes the real clock (S6).
pub type Timestamp = i64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub digest: Digest,
    pub size: u64,
    pub atime_ns: Timestamp,
}

/// One side effect. The executor performs it and, in tests, logs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Create `path` (0600, exclusive) holding `bytes`.
    Write { path: PathBuf, bytes: Vec<u8> },
    Fsync { path: PathBuf },
    Rename { from: PathBuf, to: PathBuf },
    /// One transaction: insert `insert`, delete the records of `delete`.
    Commit {
        insert: Option<Record>,
        delete: Vec<Digest>,
    },
    Unlink { path: PathBuf },
}

pub trait StepExecutor {
    fn step(&mut self, effect: &Effect) -> io::Result<()>;
}

/// Performs effects against the real filesystem and `index.db` of a store.
pub struct FsExecutor<'a> {
    pub store: &'a Store,
}

impl StepExecutor for FsExecutor<'_> {
    fn step(&mut self, effect: &Effect) -> io::Result<()> {
        let _ = effect;
        todo!("perform one effect")
    }
}

/// An in-flight file: 0600 in `cache/tmp/`, `flock`ed for its fetch's life.
pub struct TmpFile {
    pub file: File,
    pub path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("content does not hash to the requested digest")]
    Mismatch,
    #[error("cannot read the candidate: {0}")]
    Io(#[from] io::Error),
}

/// A tmp file whose entire content was hashed and equalled the digest (F2).
/// Only [`Verified::check`] builds one; admit and `cat` accept nothing else.
pub struct Verified {
    tmp: TmpFile,
    digest: Digest,
    size: u64,
}

impl Verified {
    /// Hashes all of `tmp` from offset 0.
    pub fn check(tmp: TmpFile, want: &Fetchable) -> Result<Verified, VerifyError> {
        let _ = (tmp, want);
        todo!("ES-8 full hash")
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn tmp(&self) -> &TmpFile {
        &self.tmp
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache: {0}")]
    Io(#[from] io::Error),
    #[error("cache: {0}")]
    Store(String),
}

pub struct Cache<'a> {
    store: &'a Store,
    capacity: u64,
}

impl<'a> Cache<'a> {
    pub fn new(store: &'a Store, capacity: u64) -> Cache<'a> {
        Cache { store, capacity }
    }

    /// `cache/<ALG>/<HEX>` with the digest in uppercase hex (ES-24), relative
    /// to the store directory.
    pub fn relative_path(d: &Digest) -> PathBuf {
        let _ = d;
        todo!("ES-24 name")
    }

    /// A fresh locked 0600 file in `cache/tmp/`, creating directories 0700.
    pub fn create_tmp(&self) -> io::Result<TmpFile> {
        let _ = (self.store, self.capacity);
        todo!("ES-24 tmp")
    }

    /// Fsync, rename into the final name, then one commit that inserts the
    /// record and evicts until the capacity holds (ES-26); unlinks follow.
    pub fn admit(
        &self,
        lock: &WriteLock,
        ex: &mut dyn StepExecutor,
        v: Verified,
        now: Timestamp,
    ) -> Result<(), CacheError> {
        let _ = (lock, ex, v, now);
        todo!("ES-8 admit")
    }

    /// Deletes the record (commit), then unlinks the file.
    pub fn evict(
        &self,
        lock: &WriteLock,
        ex: &mut dyn StepExecutor,
        d: &Digest,
    ) -> Result<(), CacheError> {
        let _ = (lock, ex, d);
        todo!("evict")
    }

    /// The file for `d` if the record's file is a regular file, opened without
    /// following symlinks, of the recorded size (ES-10). Otherwise `None`,
    /// and the record and file are evicted if the lock is free.
    pub fn lookup(&self, d: &Digest, ex: &mut dyn StepExecutor) -> Result<Option<PathBuf>, CacheError> {
        let _ = (d, ex);
        todo!("ES-10")
    }

    /// `atime := max(now, atime)` under a non-blocking lock attempt; `false`
    /// when skipped because the lock was busy (ES-27).
    pub fn touch(&self, d: &Digest, now: Timestamp) -> Result<bool, CacheError> {
        let _ = (d, now);
        todo!("ES-27")
    }

    pub fn records(&self) -> Result<Vec<Record>, CacheError> {
        todo!("read the cache table")
    }

    /// Deletes files without a record and unlocked temporary files older than
    /// 60 s relative to `now` (ES-30).
    pub fn sweep(
        &self,
        lock: &WriteLock,
        ex: &mut dyn StepExecutor,
        now: SystemTime,
    ) -> Result<(), CacheError> {
        let _ = (lock, ex, now);
        todo!("ES-30")
    }

    pub fn dir(&self) -> PathBuf {
        todo!("<store>/cache")
    }
}
