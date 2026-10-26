//! Store location, ownership checks, locking and registry access.

use crate::registry::{self, RegPath, RegistryErrorKind};
use rustix::fs::{
    flock, fstat, fsync, mkdirat, openat, renameat, renameat_with, statat, unlinkat, AtFlags,
    FileType, FlockOperation, Mode, OFlags, RenameFlags, CWD,
};
use rustix::io::Errno;
use rustix::process::geteuid;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const REGISTRY: &str = "registry";
const INDEX_DB: &str = "index.db";
const LOCK: &str = "lock";
const REGISTRY_TMP: &str = "registry.tmp";
const FILES: [&str; 3] = [REGISTRY, INDEX_DB, LOCK];
const S_ISVTX: u32 = 0o1000;

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
    #[error("{}: line {line}: {kind:?}", path.display())]
    Registry {
        path: PathBuf,
        line: usize,
        kind: RegistryErrorKind,
    },
    #[error("store directory {0} is no longer the directory that was opened")]
    Moved(PathBuf),
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

/// The directory fd is held, so the owner/mode checks, the registry, the lock
/// and the temp files all go through the inode that was checked. `index.db` is
/// the exception: SQLite opens it by path. That is guarded by the ancestor
/// check in `open` plus an identity re-check in `Index::open`, not by the fd.
pub struct Store {
    dir: OwnedFd,
    path: PathBuf,
    id: (u64, u64),
}

pub struct WriteLock {
    _fd: OwnedFd,
    store: (u64, u64),
}

/// Pure owner/mode judgement on raw `st_uid`/`st_mode`; `Foreign` takes
/// precedence over `Writable`.
pub fn judge_owner_mode(uid: u32, mode: u32, euid: u32, path: &Path) -> Result<(), StoreError> {
    if uid != euid {
        return Err(StoreError::Foreign {
            path: path.to_path_buf(),
            uid,
        });
    }
    if mode & 0o022 != 0 {
        return Err(StoreError::Writable(path.to_path_buf()));
    }
    Ok(())
}

/// Pure ancestor judgement (OpenSSH StrictModes style): owner must be root
/// or `euid`, and the directory must not be group/other-writable unless
/// sticky. A foreign owner is refused even when sticky, since the owner can
/// still rename entries out from under us.
pub fn judge_ancestor(uid: u32, mode: u32, euid: u32, path: &Path) -> Result<(), StoreError> {
    let trusted_owner = uid == 0 || uid == euid;
    let writable = mode & 0o022 != 0 && mode & S_ISVTX == 0;
    if !trusted_owner || writable {
        return Err(StoreError::UnsafeAncestor(path.to_path_buf()));
    }
    Ok(())
}

/// Judges `start` and every directory above it, both lexically and after
/// symlink resolution: a symlinked component sends resolution through
/// directories that never appear in the lexical chain.
fn check_ancestors(start: &Path) -> Result<(), StoreError> {
    let euid = geteuid().as_raw();
    let mut chain: Vec<PathBuf> = start.ancestors().map(Path::to_path_buf).collect();
    if let Ok(real) = fs::canonicalize(start) {
        chain.extend(real.ancestors().map(Path::to_path_buf));
    }
    let mut seen = HashSet::new();
    for p in chain {
        if !seen.insert(p.clone()) {
            continue;
        }
        let md = fs::metadata(&p).map_err(|e| wrap(e, "stat ancestor", &p))?;
        judge_ancestor(md.uid(), md.mode(), euid, &p)?;
    }
    Ok(())
}

fn errno(e: Errno, what: &str, path: &Path) -> StoreError {
    wrap(e, what, path)
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn create_flags() -> OFlags {
    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn absolute(path: &Path) -> Result<PathBuf, StoreError> {
    std::path::absolute(path).map_err(|e| wrap(e, "resolve", path))
}

impl Store {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Errors unless `path` still names the directory this store holds.
    pub(crate) fn check_unmoved(&self) -> Result<(), StoreError> {
        let md = fs::symlink_metadata(&self.path)
            .map_err(|e| wrap(e, "stat store directory", &self.path))?;
        if (md.dev(), md.ino()) != self.id {
            return Err(StoreError::Moved(self.path.clone()));
        }
        Ok(())
    }

    /// Judges an open directory fd and its files. `ancestors`, when given, is
    /// the directory whose chain must be trustworthy; that check runs before
    /// the file checks.
    fn adopt(dir: OwnedFd, path: PathBuf, ancestors: Option<&Path>) -> Result<Store, StoreError> {
        let euid = geteuid().as_raw();
        let st = fstat(&dir).map_err(|e| errno(e, "stat store directory", &path))?;
        judge_owner_mode(st.st_uid, st.st_mode, euid, &path)?;
        if let Some(start) = ancestors {
            check_ancestors(start)?;
        }
        for name in FILES {
            let p = path.join(name);
            match statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(fst) => {
                    if !FileType::from_raw_mode(fst.st_mode).is_file() {
                        return Err(StoreError::NotAStore(path));
                    }
                    judge_owner_mode(fst.st_uid, fst.st_mode, euid, &p)?;
                }
                // `lock` is created on demand.
                Err(Errno::NOENT) if name == LOCK => {}
                Err(Errno::NOENT) => return Err(StoreError::NotAStore(path)),
                Err(e) => return Err(errno(e, "stat", &p)),
            }
        }
        Ok(Store {
            id: (st.st_dev as u64, st.st_ino as u64),
            dir,
            path,
        })
    }

    pub fn open(path: &Path) -> Result<Store, StoreError> {
        let abs = absolute(path)?;
        let dir = openat(CWD, &abs, DIR_FLAGS, Mode::empty())
            .map_err(|e| errno(e, "open store directory", &abs))?;
        let parent = abs.parent().map(Path::to_path_buf);
        Store::adopt(dir, abs, parent.as_deref())
    }

    /// Fails with `AlreadyExists` rather than touching an existing path.
    pub fn init_bare(path: &Path) -> Result<Store, StoreError> {
        Store::init_bare_with(path, &mut |_| Ok(()))
    }

    /// Like `init_bare`, but `before_publish` runs with the fully built
    /// temp sibling's path just before it is renamed into place; an `Err`
    /// aborts the init and nothing remains on disk.
    pub fn init_bare_with(
        path: &Path,
        before_publish: &mut dyn FnMut(&Path) -> io::Result<()>,
    ) -> Result<Store, StoreError> {
        let abs = absolute(path)?;
        publish_new(&abs, &[], before_publish)
    }

    /// `<dir>/.ext`, with `dir` (canonicalised) as its first registered root.
    pub fn init_extant(dir: &Path) -> Result<Store, StoreError> {
        Store::init_extant_with(dir, &mut |_| Ok(()))
    }

    /// Like `init_extant`; the temp store already holds its registry root
    /// when `before_publish` runs, so a store is never visible without it.
    pub fn init_extant_with(
        dir: &Path,
        before_publish: &mut dyn FnMut(&Path) -> io::Result<()>,
    ) -> Result<Store, StoreError> {
        let canon = fs::canonicalize(dir).map_err(|e| wrap(e, "canonicalise", dir))?;
        let root = RegPath::from_bytes(canon.as_os_str().as_bytes()).map_err(|k| {
            wrap(
                io::Error::new(io::ErrorKind::InvalidData, format!("{k:?}")),
                "not a valid registry root:",
                &canon,
            )
        })?;
        publish_new(
            &canon.join(".ext"),
            &registry::render(&[root]),
            before_publish,
        )
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
        judge_owner_mode(st.st_uid, st.st_mode, geteuid().as_raw(), &p)?;
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
        registry::parse(&bytes).map_err(|(line, kind)| StoreError::Registry {
            path: p,
            line,
            kind,
        })
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
        write_new_file(&self.dir, REGISTRY_TMP, bytes, &tmp)?;
        renameat(&self.dir, REGISTRY_TMP, &self.dir, REGISTRY)
            .map_err(|e| errno(e, "rename onto registry in", &self.path))?;
        fsync(self.dir.as_fd()).map_err(|e| errno(e, "sync store directory", &self.path))
    }
}

/// Creates `name` exclusively (never through a symlink), writes and syncs it.
fn write_new_file(dir: &OwnedFd, name: &str, bytes: &[u8], shown: &Path) -> Result<(), StoreError> {
    let fd = openat(dir, name, create_flags(), Mode::RUSR | Mode::WUSR)
        .map_err(|e| errno(e, "create", shown))?;
    let mut file = fs::File::from(fd);
    file.write_all(bytes).map_err(|e| wrap(e, "write", shown))?;
    file.sync_all().map_err(|e| wrap(e, "sync", shown))
}

/// Builds a store in a temp sibling of `target` through a held parent fd, runs
/// the hook, and publishes with `RENAME_NOREPLACE`. Any failure removes the
/// temp (or the published store), so a store never exists half-built or
/// without its initial registry content.
fn publish_new(
    target: &Path,
    registry_bytes: &[u8],
    before_publish: &mut dyn FnMut(&Path) -> io::Result<()>,
) -> Result<Store, StoreError> {
    let (Some(parent), Some(name)) = (target.parent(), target.file_name().and_then(OsStr::to_str))
    else {
        return Err(wrap(
            io::Error::from(io::ErrorKind::InvalidInput),
            "cannot create a store at",
            target,
        ));
    };
    let pfd = openat(
        CWD,
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| errno(e, "open parent directory", parent))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let tmp_name = format!(".{name}.init-{}-{nanos}", std::process::id());
    let tmp_path = parent.join(&tmp_name);

    let mut published = false;
    let result = (|| {
        mkdirat(&pfd, tmp_name.as_str(), Mode::RWXU)
            .map_err(|e| errno(e, "create temp store", &tmp_path))?;
        let dir = openat(&pfd, tmp_name.as_str(), DIR_FLAGS, Mode::empty())
            .map_err(|e| errno(e, "open temp store", &tmp_path))?;
        for f in FILES {
            let bytes: &[u8] = if f == REGISTRY { registry_bytes } else { &[] };
            write_new_file(&dir, f, bytes, &tmp_path.join(f))?;
        }
        fsync(&dir).map_err(|e| errno(e, "sync temp store", &tmp_path))?;
        // Judged before publish so a bad store leaves nothing behind; the fd
        // stays valid across the rename. Ancestors are not judged here: that
        // is `open`'s job, and init in a loose parent is allowed.
        let store = Store::adopt(dir, target.to_path_buf(), None)?;
        before_publish(&tmp_path)
            .map_err(|e| wrap(e, "init aborted before publish for", target))?;
        renameat_with(&pfd, tmp_name.as_str(), &pfd, name, RenameFlags::NOREPLACE)
            .map_err(|e| errno(e, "publish store at", target))?;
        published = true;
        fsync(&pfd).map_err(|e| errno(e, "sync parent directory", parent))?;
        Ok(store)
    })();
    if result.is_err() {
        let victim = if published { name } else { tmp_name.as_str() };
        for f in FILES.iter().chain(std::iter::once(&REGISTRY_TMP)) {
            let _ = unlinkat(&pfd, format!("{victim}/{f}").as_str(), AtFlags::empty());
        }
        let _ = unlinkat(&pfd, victim, AtFlags::REMOVEDIR);
    }
    result
}
