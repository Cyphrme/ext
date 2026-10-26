//! Store location, ownership checks, locking and registry access.

use crate::registry::{self, RegPath, RegistryErrorKind};
use rustix::fs::{
    flock, fstat, fsync, openat, renameat, statat, unlinkat, AtFlags, FileType, FlockOperation,
    Mode, OFlags, Stat, CWD,
};
use rustix::io::Errno;
use rustix::process::geteuid;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

const REGISTRY: &str = "registry";
const INDEX_DB: &str = "index.db";
const LOCK: &str = "lock";
const REGISTRY_TMP: &str = "registry.tmp";

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
    #[error("ancestor directory is not trustworthy (foreign owner or writable by others): {0}")]
    UnsafeAncestor(PathBuf),
    #[error("registry line {line}: {kind:?}")]
    Registry {
        line: usize,
        kind: RegistryErrorKind,
    },
    #[error("not a registered root: {0}")]
    NotRegistered(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("db: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("index schema version {found} is not supported (expected {expected})")]
    Schema { found: i64, expected: i64 },
    #[error("corrupt index row: {0}")]
    Corrupt(String),
}

/// Io error that keeps the kind (callers match on `AlreadyExists`) but says
/// what failed and where.
pub(crate) fn wrap(e: impl Into<io::Error>, what: &str, path: &Path) -> StoreError {
    let e = e.into();
    StoreError::Io(io::Error::new(
        e.kind(),
        format!("{what} {}: {e}", path.display()),
    ))
}

fn is_store(dir: &Path) -> bool {
    [REGISTRY, INDEX_DB]
        .iter()
        .all(|f| fs::symlink_metadata(dir.join(f)).is_ok_and(|m| m.is_file()))
}

/// An explicit path may be a store, or a directory whose `.ext` is one.
/// Resolution never falls through from an explicit path to a lower step.
fn explicit(p: &Path) -> Result<PathBuf, StoreError> {
    match fs::symlink_metadata(p) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(StoreError::ExplicitMissing(p.to_path_buf()))
        }
        Err(e) => return Err(wrap(e, "stat", p)),
    }
    if is_store(p) {
        return Ok(p.to_path_buf());
    }
    let sub = p.join(".ext");
    if is_store(&sub) {
        return Ok(sub);
    }
    Err(StoreError::NotAStore(p.to_path_buf()))
}

/// Order (spec, PR #12): flag, `EXTANT_DIR` (empty counts as unset), system
/// default, `./.ext`.
pub fn locate(
    flag: Option<&Path>,
    env: Option<&OsStr>,
    default: &Path,
    cwd: &Path,
) -> Result<(PathBuf, Source), StoreError> {
    if let Some(p) = flag {
        return Ok((explicit(p)?, Source::Flag));
    }
    if let Some(p) = env.filter(|v| !v.is_empty()) {
        return Ok((explicit(Path::new(p))?, Source::Env));
    }
    if is_store(default) {
        return Ok((default.to_path_buf(), Source::Default));
    }
    let sub = cwd.join(".ext");
    if is_store(&sub) {
        return Ok((sub, Source::Cwd));
    }
    Err(StoreError::NoStore)
}

/// The directory fd is held so ownership checks and every later access go
/// through one inode, immune to a path swap after `open`.
pub struct Store {
    dir: OwnedFd,
    path: PathBuf,
    id: (u64, u64),
}

pub struct WriteLock {
    _fd: OwnedFd,
    store: (u64, u64),
}

fn check_owner_mode(st: &Stat, path: &Path) -> Result<(), StoreError> {
    if st.st_uid != geteuid().as_raw() {
        return Err(StoreError::Foreign {
            path: path.to_path_buf(),
            uid: st.st_uid,
        });
    }
    if st.st_mode & 0o022 != 0 {
        return Err(StoreError::Writable(path.to_path_buf()));
    }
    Ok(())
}

fn errno(e: Errno, what: &str, path: &Path) -> StoreError {
    wrap(e, what, path)
}

impl Store {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub fn open(path: &Path) -> Result<Store, StoreError> {
        let abs = std::path::absolute(path).map_err(|e| wrap(e, "resolve", path))?;
        let dir = openat(
            CWD,
            &abs,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| errno(e, "open store directory", &abs))?;
        let st = fstat(&dir).map_err(|e| errno(e, "stat store directory", &abs))?;
        check_owner_mode(&st, &abs)?;
        for (name, required) in [(REGISTRY, true), (INDEX_DB, true), (LOCK, false)] {
            let p = abs.join(name);
            match statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(fst) => {
                    if !FileType::from_raw_mode(fst.st_mode).is_file() {
                        return Err(StoreError::NotAStore(abs));
                    }
                    check_owner_mode(&fst, &p)?;
                }
                Err(Errno::NOENT) if !required => {}
                Err(Errno::NOENT) => return Err(StoreError::NotAStore(abs)),
                Err(e) => return Err(errno(e, "stat", &p)),
            }
        }
        Ok(Store {
            id: (st.st_dev as u64, st.st_ino as u64),
            dir,
            path: abs,
        })
    }

    /// Fails with `AlreadyExists` rather than touching an existing path.
    pub fn init_bare(path: &Path) -> Result<Store, StoreError> {
        let abs = std::path::absolute(path).map_err(|e| wrap(e, "resolve", path))?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&abs)
            .map_err(|e| wrap(e, "create store directory", &abs))?;
        let dir = openat(
            CWD,
            &abs,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| errno(e, "open store directory", &abs))?;
        for name in [REGISTRY, INDEX_DB, LOCK] {
            openat(
                &dir,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|e| errno(e, "create", &abs.join(name)))?;
        }
        fsync(&dir).map_err(|e| errno(e, "sync store directory", &abs))?;
        Store::open(&abs)
    }

    /// `<dir>/.ext`, with `dir` (canonicalised) as its first registered root.
    pub fn init_extant(dir: &Path) -> Result<Store, StoreError> {
        let canon = fs::canonicalize(dir).map_err(|e| wrap(e, "canonicalise", dir))?;
        let root = RegPath::from_bytes(canon.as_os_str().as_bytes())
            .map_err(|kind| StoreError::Registry { line: 0, kind })?;
        let store = Store::init_bare(&canon.join(".ext"))?;
        let lock = store.lock()?;
        store.edit_registry(&lock, |v| v.push(root))?;
        drop(lock);
        Ok(store)
    }

    /// `(dev, ino)` of the store directory, taken from its held fd.
    pub fn id(&self) -> (u64, u64) {
        self.id
    }

    /// Blocks until the exclusive lock is held. The lock is its own file
    /// because the registry is replaced by rename: a lock on the registry
    /// inode would not exclude the next writer.
    pub fn lock(&self) -> Result<WriteLock, StoreError> {
        let p = self.path.join(LOCK);
        let fd = openat(
            &self.dir,
            LOCK,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| errno(e, "open lock", &p))?;
        let st = fstat(&fd).map_err(|e| errno(e, "stat lock", &p))?;
        if !FileType::from_raw_mode(st.st_mode).is_file() {
            return Err(StoreError::NotAStore(self.path.clone()));
        }
        check_owner_mode(&st, &p)?;
        loop {
            match flock(&fd, FlockOperation::LockExclusive) {
                Ok(()) => break,
                Err(Errno::INTR) => continue,
                Err(e) => return Err(errno(e, "flock", &p)),
            }
        }
        Ok(WriteLock {
            _fd: fd,
            store: self.id,
        })
    }

    pub fn registry(&self) -> Result<Vec<RegPath>, StoreError> {
        let p = self.path.join(REGISTRY);
        let fd = openat(
            &self.dir,
            REGISTRY,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| errno(e, "open", &p))?;
        let mut bytes = Vec::new();
        fs::File::from(fd)
            .read_to_end(&mut bytes)
            .map_err(|e| wrap(e, "read", &p))?;
        registry::parse(&bytes).map_err(|(line, kind)| StoreError::Registry { line, kind })
    }

    /// Reads, applies `f`, then replaces the registry atomically. A registry
    /// that fails to parse is returned as an error, never overwritten, so a
    /// hand edit with a typo is not silently discarded.
    pub fn edit_registry(
        &self,
        lock: &WriteLock,
        f: impl FnOnce(&mut Vec<RegPath>),
    ) -> Result<(), StoreError> {
        if lock.store != self.id {
            return Err(wrap(
                io::Error::from(io::ErrorKind::InvalidInput),
                "lock belongs to a different store than",
                &self.path,
            ));
        }
        let mut paths = self.registry()?;
        f(&mut paths);
        let mut seen = HashSet::new();
        paths.retain(|p| seen.insert(p.clone()));
        let bytes = registry::render(&paths);
        let result = self.replace_registry(&bytes);
        if result.is_err() {
            // Best effort: a leftover temp is also cleared by the next write.
            let _ = unlinkat(&self.dir, REGISTRY_TMP, AtFlags::empty());
        }
        result
    }

    fn replace_registry(&self, bytes: &[u8]) -> Result<(), StoreError> {
        let tmp = self.path.join(REGISTRY_TMP);
        // The lock is held, so any existing temp is a crashed writer's.
        match unlinkat(&self.dir, REGISTRY_TMP, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(e) => return Err(errno(e, "remove stale", &tmp)),
        }
        let fd = openat(
            &self.dir,
            REGISTRY_TMP,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| errno(e, "create", &tmp))?;
        let mut file = fs::File::from(fd);
        file.write_all(bytes).map_err(|e| wrap(e, "write", &tmp))?;
        file.sync_all().map_err(|e| wrap(e, "sync", &tmp))?;
        renameat(&self.dir, REGISTRY_TMP, &self.dir, REGISTRY)
            .map_err(|e| errno(e, "rename onto registry in", &self.path))?;
        fsync(self.dir.as_fd()).map_err(|e| errno(e, "sync store directory", &self.path))
    }
}

/// Pure owner/mode judgement on raw `st_uid`/`st_mode`; `Store::open` and
/// `lock` must delegate to it. `Foreign` takes precedence over `Writable`.
pub fn judge_owner_mode(_uid: u32, _mode: u32, _euid: u32, _path: &Path) -> Result<(), StoreError> {
    todo!("step 2 rework: pure owner/mode check")
}

/// Pure ancestor judgement (OpenSSH StrictModes style): owner must be root
/// or `euid`, and the directory must not be group/other-writable unless
/// sticky. Failure is `UnsafeAncestor(path)`.
pub fn judge_ancestor(_uid: u32, _mode: u32, _euid: u32, _path: &Path) -> Result<(), StoreError> {
    todo!("step 2 rework: pure ancestor check")
}

impl Store {
    /// Like `init_bare`, but `before_publish` runs with the fully built
    /// temp sibling's path just before it is renamed into place; an `Err`
    /// aborts the init and nothing may remain on disk.
    pub fn init_bare_with(
        _path: &Path,
        _before_publish: &mut dyn FnMut(&Path) -> io::Result<()>,
    ) -> Result<Store, StoreError> {
        todo!("step 2 rework: atomic init via temp sibling and renameat2")
    }

    /// Like `init_extant`; the temp store already holds its registry root
    /// when `before_publish` runs.
    pub fn init_extant_with(
        _dir: &Path,
        _before_publish: &mut dyn FnMut(&Path) -> io::Result<()>,
    ) -> Result<Store, StoreError> {
        todo!("step 2 rework: atomic init via temp sibling and renameat2")
    }
}
