//! Store location, ownership checks, locking and registry access.

use crate::registry::{RegPath, RegistryErrorKind};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Flag,
    Env,
    Default,
    Cwd,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("explicit store path does not exist: {0}")]
    ExplicitMissing(PathBuf),
    #[error("no store found")]
    NoStore,
    #[error("not a store: {0}")]
    NotAStore(PathBuf),
    #[error("store {path} is owned by uid {uid}, not the effective user")]
    Foreign { path: PathBuf, uid: u32 },
    #[error("store path is group- or other-writable: {0}")]
    Writable(PathBuf),
    #[error("registry line {line}: {kind:?}")]
    Registry {
        line: usize,
        kind: RegistryErrorKind,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("db: {0}")]
    Db(#[from] rusqlite::Error),
}

pub fn locate(
    _flag: Option<&Path>,
    _env: Option<&OsStr>,
    _default: &Path,
    _cwd: &Path,
) -> Result<(PathBuf, Source), StoreError> {
    todo!("step 2: store resolution")
}

pub struct Store {
    _private: (),
}

pub struct WriteLock {
    _private: (),
}

impl Store {
    pub fn open(_path: &Path) -> Result<Store, StoreError> {
        todo!("step 2: open with owner/mode checks")
    }

    pub fn init_extant(_dir: &Path) -> Result<Store, StoreError> {
        todo!("step 2: create <dir>/.ext and register dir")
    }

    pub fn init_bare(_path: &Path) -> Result<Store, StoreError> {
        todo!("step 2: create flat store")
    }

    /// `(dev, ino)` of the store directory, taken from its held fd.
    pub fn id(&self) -> (u64, u64) {
        todo!("step 2: fstat the held dir fd")
    }

    pub fn lock(&self) -> Result<WriteLock, StoreError> {
        todo!("step 2: flock")
    }

    pub fn registry(&self) -> Result<Vec<RegPath>, StoreError> {
        todo!("step 2: read registry")
    }

    pub fn edit_registry(
        &self,
        _lock: &WriteLock,
        _f: impl FnOnce(&mut Vec<RegPath>),
    ) -> Result<(), StoreError> {
        todo!("step 2: atomic registry rewrite")
    }
}
