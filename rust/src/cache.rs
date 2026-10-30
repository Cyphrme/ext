//! The blob cache (ES-8, ES-10, ES-24 to ES-27, ES-30): records in the
//! `cache` table of `index.db`, files under `<store>/cache/<ALG>/<HEX>`.
//!
//! Every effect of admit, evict, sweep and the services-file write goes
//! through a [`StepExecutor`], so a test executor can drop effect k and every
//! later one and model a killed process.

use crate::digest::{Alg, Digest, Enc};
use crate::index::Index;
use crate::services::Fetchable;
use crate::store::{Store, StoreError, WriteLock};
use rusqlite::params;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Nanoseconds since the epoch; the CLI passes the real clock (S6).
pub type Timestamp = i64;

const CACHE: &str = "cache";
const TMP: &str = "tmp";

/// ES-30: a temporary younger than this may not be locked yet.
const TMP_AGE_FLOOR: Duration = Duration::from_secs(60);

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
    Write {
        path: PathBuf,
        bytes: Vec<u8>,
    },
    Fsync {
        path: PathBuf,
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
    },
    /// One transaction: insert `insert`, delete the records of `delete`.
    Commit {
        insert: Option<Record>,
        delete: Vec<Digest>,
    },
    Unlink {
        path: PathBuf,
    },
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
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let at = |e: io::Error, what: &str, p: &Path| {
            io::Error::new(e.kind(), format!("{what} {}: {e}", p.display()))
        };
        match effect {
            Effect::Write { path, bytes } => {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path)
                    .map_err(|e| at(e, "create", path))?;
                // The mode above passed through the umask; state it outright.
                f.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| at(e, "chmod", path))?;
                f.write_all(bytes).map_err(|e| at(e, "write", path))
            }
            Effect::Fsync { path } => File::open(path)
                .and_then(|f| f.sync_all())
                .map_err(|e| at(e, "sync", path)),
            Effect::Rename { from, to } => {
                std::fs::rename(from, to).map_err(|e| at(e, "rename onto", to))?;
                if let Some(dir) = to.parent() {
                    File::open(dir)
                        .and_then(|d| d.sync_all())
                        .map_err(|e| at(e, "sync directory", dir))?;
                }
                Ok(())
            }
            Effect::Commit { insert, delete } => commit(self.store, insert.as_ref(), delete)
                .map_err(|e| io::Error::other(format!("cache record commit: {e}"))),
            Effect::Unlink { path } => match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(at(e, "remove", path)),
            },
        }
    }
}

fn commit(store: &Store, insert: Option<&Record>, delete: &[Digest]) -> Result<(), StoreError> {
    let idx = Index::open(store)?;
    let tx = idx.write_tx()?;
    for d in delete {
        tx.execute(
            "DELETE FROM cache WHERE alg = ?1 AND digest = ?2",
            params![d.alg().name(), d.bytes()],
        )?;
    }
    if let Some(r) = insert {
        // A re-admission keeps the later atime, as a touch does.
        tx.execute(
            "INSERT INTO cache (alg, digest, size, atime_ns) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (alg, digest) DO UPDATE SET
                 size = excluded.size,
                 atime_ns = max(atime_ns, excluded.atime_ns)",
            params![
                r.digest.alg().name(),
                r.digest.bytes(),
                r.size as i64,
                r.atime_ns
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// An in-flight file: 0600 in `cache/tmp/`, `flock`ed for its fetch's life.
/// It is deleted when dropped unless [`TmpFile::persist`] ran, so cleanup on
/// every error path is structural and no caller has to remember it.
pub struct TmpFile {
    file: File,
    path: PathBuf,
    persisted: bool,
}

impl TmpFile {
    /// A file with no name on disk (nothing to delete on drop): for stubs and
    /// in-memory sinks.
    pub fn anonymous(file: File) -> TmpFile {
        TmpFile {
            file,
            path: PathBuf::new(),
            persisted: false,
        }
    }

    pub fn file(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Admit calls this once the file has its final name.
    pub(crate) fn persist(&mut self) {
        self.persisted = true;
    }
}

impl Drop for TmpFile {
    fn drop(&mut self) {
        if !self.persisted && !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
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
        let want = want.digest();
        let (digest, meta) =
            crate::hash::hash_stable(&tmp.file, want.alg(), &mut |_| {}).map_err(|e| match e {
                crate::hash::HashError::Io(e) => VerifyError::Io(e),
                // Only another process could change our private file.
                crate::hash::HashError::Unstable => VerifyError::Io(io::Error::other(
                    "the candidate changed while it was being hashed",
                )),
            })?;
        if digest != *want {
            return Err(VerifyError::Mismatch);
        }
        Ok(Verified {
            tmp,
            digest,
            size: meta.size,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn path(&self) -> &Path {
        self.tmp.path()
    }

    /// A second handle on the verified content, which stays valid after
    /// admit renames the file: `cat` delivers through it (ES-11, ES-25).
    pub fn reopen(&self) -> io::Result<File> {
        self.tmp.file.try_clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache: {0}")]
    Io(#[from] io::Error),
    #[error("cache: {0}")]
    Store(String),
}

impl From<StoreError> for CacheError {
    fn from(e: StoreError) -> CacheError {
        CacheError::Store(e.to_string())
    }
}

impl From<rusqlite::Error> for CacheError {
    fn from(e: rusqlite::Error) -> CacheError {
        CacheError::Store(e.to_string())
    }
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
        Path::new(CACHE)
            .join(d.alg().name())
            .join(d.encode(Enc::Hex))
    }

    /// ES-21: `cache/` and its directories, where present, pass the store's
    /// owner check.
    pub fn check(&self) -> Result<(), CacheError> {
        if self.store.check_subdir(Path::new(CACHE))? {
            let sub = Alg::ALL.iter().map(|a| a.name()).chain([TMP]);
            for s in sub {
                self.store.check_subdir(&Path::new(CACHE).join(s))?;
            }
        }
        Ok(())
    }

    /// A fresh locked 0600 file in `cache/tmp/`, creating directories 0700.
    pub fn create_tmp(&self) -> io::Result<TmpFile> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let base = self.store.path().join(CACHE);
        let dirs = [base.clone(), base.join(TMP)]
            .into_iter()
            .chain(Alg::ALL.iter().map(|a| base.join(a.name())));
        for d in dirs {
            match std::fs::DirBuilder::new().mode(0o700).create(&d) {
                Ok(()) => std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| io::Error::new(e.kind(), format!("chmod {}: {e}", d.display())))?,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("create {}: {e}", d.display()),
                    ))
                }
            }
        }
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let name = format!(
            "{}-{nanos}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let path = base.join(TMP).join(name);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("create {}: {e}", path.display())))?;
        // From here on, dropping `tmp` removes the file on every error path.
        let tmp = TmpFile {
            file,
            path,
            persisted: false,
        };
        tmp.file
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        // Sweep tells a live fetch's file from a dead one by this lock (ES-30).
        rustix::fs::flock(
            &tmp.file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )?;
        Ok(tmp)
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
        self.own(lock)?;
        let mut v = v;
        if v.path().as_os_str().is_empty() {
            return Err(CacheError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "admit needs a file in cache/tmp, not an anonymous one",
            )));
        }
        self.sweep(lock, ex, SystemTime::now())?;
        let final_path = self.store.path().join(Self::relative_path(&v.digest));
        ex.step(&Effect::Fsync {
            path: v.path().to_path_buf(),
        })?;
        ex.step(&Effect::Rename {
            from: v.path().to_path_buf(),
            to: final_path,
        })?;
        v.tmp.persist();

        let records = self.records()?;
        let atime = records
            .iter()
            .find(|r| r.digest == v.digest)
            .map_or(now, |r| r.atime_ns.max(now));
        let mut others: Vec<&Record> = records.iter().filter(|r| r.digest != v.digest).collect();
        others.sort_by(|a, b| (a.atime_ns, &a.digest).cmp(&(b.atime_ns, &b.digest)));
        let mut total = others.iter().map(|r| r.size).sum::<u64>() + v.size;
        let mut victims = Vec::new();
        for r in others {
            if total <= self.capacity {
                break;
            }
            total -= r.size;
            victims.push(r.digest.clone());
        }
        ex.step(&Effect::Commit {
            insert: Some(Record {
                digest: v.digest.clone(),
                size: v.size,
                atime_ns: atime,
            }),
            delete: victims.clone(),
        })?;
        // Past the commit an unlink that fails or is killed leaves an
        // orphan, which the next sweep takes (ES-26): not an error.
        for d in &victims {
            let _ = ex.step(&Effect::Unlink {
                path: self.store.path().join(Self::relative_path(d)),
            });
        }
        Ok(())
    }

    /// Deletes the record (commit), then unlinks the file; a failed unlink
    /// leaves an orphan for the next sweep (ES-26).
    pub fn evict(
        &self,
        lock: &WriteLock,
        ex: &mut dyn StepExecutor,
        d: &Digest,
    ) -> Result<(), CacheError> {
        self.own(lock)?;
        ex.step(&Effect::Commit {
            insert: None,
            delete: vec![d.clone()],
        })?;
        let _ = ex.step(&Effect::Unlink {
            path: self.store.path().join(Self::relative_path(d)),
        });
        Ok(())
    }

    /// Removes the record of `d` and, unless a directory or other special
    /// file stands there, its file; only when the lock is free right now
    /// and the store is writable (ES-10, ES-11, ES-27). Best effort: the
    /// caller goes on as on a miss whether or not it ran, so a failure
    /// leaves the stale record for a later lookup to try again.
    pub fn discard_if_free(&self, d: &Digest, ex: &mut dyn StepExecutor) {
        if self.store.read_only() {
            return;
        }
        let Ok(Some(lock)) = self.store.try_lock() else {
            return;
        };
        let commit = Effect::Commit {
            insert: None,
            delete: vec![d.clone()],
        };
        if ex.step(&commit).is_err() {
            return;
        }
        let path = self.store.path().join(Self::relative_path(d));
        // A symlink is removed (unlink never follows it); a directory or a
        // device is left for its owner to look at.
        if let Ok(md) = path.symlink_metadata() {
            if md.file_type().is_file() || md.file_type().is_symlink() {
                let _ = ex.step(&Effect::Unlink { path });
            }
        }
        drop(lock);
    }

    /// The file for `d`, opened for reading, if the record's file is a
    /// regular file of the recorded size, not reached through a symlink
    /// (ES-10). Otherwise `None`, and the record and file are evicted if the
    /// lock is free.
    pub fn lookup(
        &self,
        d: &Digest,
        ex: &mut dyn StepExecutor,
    ) -> Result<Option<File>, CacheError> {
        let Some(rec) = self.record(d)? else {
            return Ok(None);
        };
        let rel = Self::relative_path(d);
        let answers = |m: &std::fs::Metadata| m.is_file() && m.len() == rec.size;
        // Opening a FIFO or device has effects even without blocking, so the
        // type is checked by name first; the open handle is checked again in
        // case the entry was replaced in between.
        let file = self
            .store
            .path()
            .join(&rel)
            .symlink_metadata()
            .is_ok_and(|m| answers(&m))
            .then(|| self.store.open_nofollow(&rel).ok())
            .flatten()
            .filter(|f| f.metadata().is_ok_and(|m| answers(&m)));
        if file.is_some() {
            return Ok(file);
        }
        self.discard_if_free(d, ex);
        Ok(None)
    }

    /// `atime := max(now, atime)` under a non-blocking lock attempt; `false`
    /// when skipped because the lock was busy (ES-27).
    pub fn touch(&self, d: &Digest, now: Timestamp) -> Result<bool, CacheError> {
        if self.store.read_only() {
            return Ok(false);
        }
        let Some(_lock) = self.store.try_lock()? else {
            return Ok(false);
        };
        let idx = Index::open(self.store)?;
        idx.conn().execute(
            "UPDATE cache SET atime_ns = max(atime_ns, ?3) WHERE alg = ?1 AND digest = ?2",
            params![d.alg().name(), d.bytes(), now],
        )?;
        Ok(true)
    }

    pub fn records(&self) -> Result<Vec<Record>, CacheError> {
        self.select(None)
    }

    fn record(&self, d: &Digest) -> Result<Option<Record>, CacheError> {
        Ok(self.select(Some(d))?.pop())
    }

    fn select(&self, only: Option<&Digest>) -> Result<Vec<Record>, CacheError> {
        let idx = Index::open_for_lookup(self.store)?;
        if !idx.has_table("cache")? {
            return Ok(Vec::new());
        }
        // A keyed statement of its own: an optional key (`?1 IS NULL OR`)
        // would keep SQLite from using the primary key.
        let all = "SELECT alg, digest, size, atime_ns FROM cache";
        let row = |r: &rusqlite::Row| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?));
        let raw: Vec<(String, Vec<u8>, i64, i64)> = match only {
            Some(d) => idx
                .conn()
                .prepare(&format!("{all} WHERE alg = ?1 AND digest = ?2"))?
                .query_map(params![d.alg().name(), d.bytes()], row)?
                .collect::<Result<_, _>>()?,
            None => idx
                .conn()
                .prepare(all)?
                .query_map([], row)?
                .collect::<Result<_, _>>()?,
        };
        raw.into_iter()
            .map(|(alg, digest, size, atime_ns)| {
                let a = Alg::from_name(&alg).ok_or_else(|| {
                    CacheError::Store(format!("cache record: unknown algorithm {alg:?}"))
                })?;
                let digest = Digest::from_bytes(a, &digest)
                    .map_err(|e| CacheError::Store(format!("cache record: {e}")))?;
                Ok(Record {
                    digest,
                    size: size as u64,
                    atime_ns,
                })
            })
            .collect()
    }

    /// Deletes files without a record and unlocked temporary files older than
    /// 60 s relative to `now` (ES-30).
    pub fn sweep(
        &self,
        lock: &WriteLock,
        ex: &mut dyn StepExecutor,
        now: SystemTime,
    ) -> Result<(), CacheError> {
        self.own(lock)?;
        let resident: HashSet<Digest> = self.records()?.into_iter().map(|r| r.digest).collect();
        let base = self.dir();
        for alg in Alg::ALL {
            let dir = base.join(alg.name());
            for (path, name) in regular_files(&dir)? {
                let known = name
                    .to_str()
                    .and_then(|n| data_encoding::HEXUPPER.decode(n.as_bytes()).ok())
                    .and_then(|b| Digest::from_bytes(*alg, &b).ok())
                    .is_some_and(|d| resident.contains(&d));
                if !known {
                    ex.step(&Effect::Unlink { path })?;
                }
            }
        }
        for (path, name) in regular_files(&base.join(TMP))? {
            let old = path
                .symlink_metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age > TMP_AGE_FLOOR);
            if !old {
                continue;
            }
            // The fetch that owns a temporary holds its flock; a free lock
            // means the owner is gone. The probe's lock is held across the
            // unlink so no new owner can appear in between.
            let Ok(probe) = self
                .store
                .open_nofollow(&Path::new(CACHE).join(TMP).join(&name))
            else {
                continue;
            };
            match rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => ex.step(&Effect::Unlink { path })?,
                Err(rustix::io::Errno::WOULDBLOCK) => {}
                Err(e) => return Err(CacheError::Io(e.into())),
            }
        }
        Ok(())
    }

    pub fn dir(&self) -> PathBuf {
        self.store.path().join(CACHE)
    }

    fn own(&self, lock: &WriteLock) -> Result<(), CacheError> {
        if self.store.holds(lock) {
            Ok(())
        } else {
            Err(CacheError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the lock belongs to another store",
            )))
        }
    }
}

/// Regular files directly in `dir` (not followed), with their names; an
/// absent directory has none.
fn regular_files(dir: &Path) -> Result<Vec<(PathBuf, OsString)>, CacheError> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(CacheError::Io(io::Error::new(
                e.kind(),
                format!("read {}: {e}", dir.display()),
            )))
        }
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        out.push((entry.path(), entry.file_name()));
    }
    Ok(out)
}
