//! Reconcile, walk, hash, classify, and write the index.

use crate::digest::{Alg, Digest};
use crate::escape::display;
use crate::fresh::{classify, should_skip, MetaCmp, Status};
use crate::hash::{hash_stable, HashError};
use crate::index::{Entry, Index, Meta, RootId};
use crate::registry::RegPath;
use crate::store::{Store, StoreError, WriteLock};
use crate::walk::{nearest_ancestor_id, walk_checked, Event};
use rustix::fs::{openat2, statx, AtFlags, FileType, Mode, OFlags, ResolveFlags, StatxFlags, CWD};
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;

/// Files per index transaction: bounds the work a crash can lose.
const BATCH: usize = 1000;

#[derive(Clone, Debug)]
pub struct Opts {
    pub full: bool,
    pub accept: bool,
    pub only: Option<RegPath>,
    /// Config `CompareCtimeInode`: false drops ctime, inode and device from
    /// the skip rule.
    pub compare_ctime_inode: bool,
    /// Config `UnregisterDeleted`: false makes a deleted root only reported.
    pub unregister_deleted: bool,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            full: false,
            accept: false,
            only: None,
            compare_ctime_inode: true,
            unregister_deleted: true,
        }
    }
}

impl Opts {
    fn meta_cmp(&self) -> MetaCmp {
        if self.compare_ctime_inode {
            MetaCmp::Full
        } else {
            MetaCmp::SizeMtime
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportKind {
    New,
    Edited,
    Violation,
    /// A violation taken as the new baseline by `--accept`.
    Accepted,
    Missing,
    /// A registered root that is gone from a filesystem still mounted.
    Deleted,
    Excluded,
    Unstable,
    Error,
    Refused,
    SubExtant,
    /// A virtual filesystem the walk did not enter.
    Mount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub kind: ReportKind,
    pub path: Vec<u8>,
    /// (stored, actual); `Some` for Edited, Violation and Accepted.
    pub digests: Option<(Digest, Digest)>,
    /// The cause; `Some(non-empty)` for Error, Refused and Unstable.
    pub detail: Option<String>,
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
    pub deleted: u64,
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
        if self.violation > 0 {
            2
        } else if self.error + self.unstable + self.refused > 0 {
            5
        } else {
            0
        }
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
///
/// The caller holds `lock` for the whole run; taking it by reference makes
/// that a type-level requirement.
pub fn run_hooked(
    store: &Store,
    lock: &WriteLock,
    idx: &Index,
    opts: &Opts,
    after_chunk: &mut dyn FnMut(&[u8], u64),
    out: &mut dyn FnMut(Report),
) -> Result<Summary, StoreError> {
    let roots = store.registry()?;
    if let Some(only) = &opts.only {
        if !roots.contains(only) {
            return Err(StoreError::NotRegistered(display(only.as_bytes())));
        }
    }
    // The registry is authoritative: entries outside it go before anything
    // is (re)indexed, whichever root is being scanned.
    idx.reconcile(&roots)?;
    let mut summary = Summary::default();
    for root in roots
        .iter()
        .filter(|r| opts.only.as_ref().is_none_or(|o| o == *r))
    {
        let mut rs = RootScan {
            store,
            lock,
            idx,
            opts,
            roots: &roots,
            summary: &mut summary,
            after_chunk: &mut *after_chunk,
            out: &mut *out,
            pending: Vec::new(),
            seen: HashSet::new(),
            unverified: HashSet::new(),
            excluded: HashSet::new(),
            root_gone: false,
            root_refused: false,
            fatal: None,
        };
        rs.scan(root, store.id())?;
    }
    Ok(summary)
}

enum Op {
    Put(Entry),
    Del(Vec<u8>),
}

struct RootScan<'a> {
    store: &'a Store,
    lock: &'a WriteLock,
    idx: &'a Index,
    opts: &'a Opts,
    roots: &'a [RegPath],
    summary: &'a mut Summary,
    after_chunk: &'a mut dyn FnMut(&[u8], u64),
    out: &'a mut dyn FnMut(Report),
    /// Index writes not yet committed; flushed at `BATCH`.
    pending: Vec<Op>,
    /// Regular files the walk reached (hashed or skipped).
    seen: HashSet<Vec<u8>>,
    /// Paths whose subtree (or content) could not be verified. Entries under
    /// them are unknown, not gone, so they are never reported Missing.
    unverified: HashSet<Vec<u8>>,
    /// Sub-extants and virtual mounts: entries under them are Excluded.
    excluded: HashSet<Vec<u8>>,
    root_gone: bool,
    root_refused: bool,
    /// First store failure; the walk cannot be aborted, so later events are
    /// dropped and the error surfaces when it returns.
    fatal: Option<StoreError>,
}

/// True if `p` equals a member of `set` or lies below one.
fn covered(set: &HashSet<Vec<u8>>, p: &[u8]) -> bool {
    set.contains(p)
        || (set.contains(&b"/"[..]) && p.first() == Some(&b'/'))
        || p.iter()
            .enumerate()
            .any(|(i, &b)| b == b'/' && i > 0 && set.contains(&p[..i]))
}

fn open_root(root: &RegPath) -> io::Result<OwnedFd> {
    Ok(openat2(
        CWD,
        root.as_bytes(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?)
}

/// True only if `path` demonstrably is no longer a regular file. Any doubt
/// (permissions, a path too long to re-resolve) counts as present: a stale
/// entry is repaired by the next scan, a deleted one is lost.
fn confirmed_absent(rootfd: &OwnedFd, root: &RegPath, path: &[u8]) -> bool {
    use rustix::io::Errno;
    let base = root.as_bytes();
    let rel = path.strip_prefix(base).unwrap_or(path);
    let rel = rel.strip_prefix(b"/").unwrap_or(rel);
    let (parent, name) = match rel.iter().rposition(|&b| b == b'/') {
        Some(i) => (&rel[..i], &rel[i + 1..]),
        None => (&b"."[..], rel),
    };
    let dir = match openat2(
        rootfd,
        parent,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => fd,
        Err(e) => return matches!(e, Errno::NOENT | Errno::NOTDIR | Errno::LOOP),
    };
    match statx(&dir, name, AtFlags::SYMLINK_NOFOLLOW, StatxFlags::TYPE) {
        Ok(st) => FileType::from_raw_mode(st.stx_mode.into()) != FileType::RegularFile,
        Err(e) => matches!(e, Errno::NOENT | Errno::NOTDIR),
    }
}

/// Why a registered root no longer opens.
#[derive(Debug, PartialEq, Eq)]
enum Gone {
    Deleted,
    /// Not a deletion, or not provably one; the string says why.
    MissingMount(String),
}

/// A root is deleted only if the filesystem it was recorded on is still
/// there: its nearest existing ancestor is on it. Anything else, including
/// not knowing, is treated as an unmounted disk, because forgetting a
/// baseline cannot be undone.
fn judge_gone(recorded: Option<RootId>, ancestor: io::Result<RootId>) -> Gone {
    match (recorded, ancestor) {
        (Some(was), Ok(now)) if was == now => Gone::Deleted,
        (Some(was), Ok(now)) => Gone::MissingMount(format!(
            "root is missing and its nearest existing ancestor is on another filesystem \
             (recorded {was}, ancestor {now}); not mounted"
        )),
        (None, _) => Gone::MissingMount(
            "root is missing and no filesystem identity was recorded for it, so a deletion \
             cannot be told from an unmounted disk"
                .into(),
        ),
        (Some(_), Err(e)) => Gone::MissingMount(format!(
            "root is missing and its nearest existing ancestor cannot be examined: {e}"
        )),
    }
}

impl RootScan<'_> {
    fn scan(&mut self, root: &RegPath, store_id: (u64, u64)) -> Result<(), StoreError> {
        let idx = self.idx;
        // Registered roots strictly inside this one belong to their own scan.
        let nested = self.nested_roots(root);
        let mut id_err: Option<StoreError> = None;
        walk_checked(
            root,
            store_id,
            &mut |id| match idx.root_id(root) {
                Ok(None) => idx.set_root_id(root, id).map_err(|e| {
                    id_err = Some(e);
                    io::Error::other("cannot record the root's filesystem identity")
                }),
                Ok(Some(was)) if was == id => Ok(()),
                Ok(Some(was)) => Err(io::Error::other(format!(
                    "filesystem identity of the root changed (was {was}, now {id}); \
                     unmounted, mounted over or replaced"
                ))),
                Err(e) => {
                    id_err = Some(e);
                    Err(io::Error::other(
                        "cannot read the root's filesystem identity",
                    ))
                }
            },
            &|p| nested.contains(p),
            &mut |_| {},
            &mut |ev| {
                if self.fatal.is_none() {
                    if let Err(e) = self.handle(ev) {
                        self.fatal = Some(e);
                    }
                }
            },
        );
        if let Some(e) = id_err.or_else(|| self.fatal.take()) {
            return Err(e);
        }
        self.flush()?;
        if self.root_gone {
            let verdict = judge_gone(self.idx.root_id(root)?, nearest_ancestor_id(root));
            match verdict {
                Gone::Deleted if !self.opts.unregister_deleted => {
                    self.summary.deleted += 1;
                    let note = "not unregistered: UnregisterDeleted is off".to_owned();
                    self.report(
                        ReportKind::Deleted,
                        root.as_bytes().to_vec(),
                        None,
                        Some(note),
                    );
                    return Ok(());
                }
                Gone::Deleted => {}
                Gone::MissingMount(why) => {
                    self.root_refused = true;
                    self.summary.refused += 1;
                    self.report(
                        ReportKind::Refused,
                        root.as_bytes().to_vec(),
                        None,
                        Some(why),
                    );
                }
            }
        }
        // A root that could not be opened for any reason but ENOENT says
        // nothing about its files; their entries stay.
        if self.root_refused {
            return Ok(());
        }
        let stored = self.idx.paths_under(root)?;
        let rootfd = if self.root_gone {
            None
        } else {
            open_root(root).ok()
        };
        let mut gone = Vec::new();
        for p in stored {
            if covered(&nested, &p) {
                continue;
            }
            let kind = if self.root_gone {
                ReportKind::Missing
            } else if self.seen.contains(&p) || covered(&self.unverified, &p) {
                continue;
            } else if covered(&self.excluded, &p) {
                ReportKind::Excluded
            } else {
                // The walk may have listed this directory before the file
                // arrived; deleting on that evidence alone would lose it.
                match &rootfd {
                    Some(fd) if !confirmed_absent(fd, root, &p) => continue,
                    None => continue,
                    _ => ReportKind::Missing,
                }
            };
            match kind {
                ReportKind::Excluded => self.summary.excluded += 1,
                _ => self.summary.missing += 1,
            }
            self.report(kind, p.clone(), None, None);
            gone.push(p);
        }
        for chunk in gone.chunks(BATCH) {
            self.idx
                .batch(|ix| chunk.iter().try_for_each(|p| ix.remove(p)))?;
        }
        if self.root_gone {
            // Registry first, as `unregister` does: if we die between the two,
            // the next run's reconcile drops what is left.
            self.store
                .edit_registry(self.lock, |v| v.retain(|r| r != root))?;
            self.idx.remove_under(root)?;
            self.summary.deleted += 1;
            self.report(ReportKind::Deleted, root.as_bytes().to_vec(), None, None);
        }
        Ok(())
    }

    fn nested_roots(&self, root: &RegPath) -> HashSet<Vec<u8>> {
        let mut prefix = root.as_bytes().to_vec();
        if prefix != b"/" {
            prefix.push(b'/');
        }
        self.roots
            .iter()
            .map(|r| r.as_bytes())
            .filter(|r| r.starts_with(&prefix) && *r != root.as_bytes())
            .map(<[u8]>::to_vec)
            .collect()
    }

    fn report(
        &mut self,
        kind: ReportKind,
        path: Vec<u8>,
        digests: Option<(Digest, Digest)>,
        detail: Option<String>,
    ) {
        (self.out)(Report {
            kind,
            path,
            digests,
            detail,
        });
    }

    fn push(&mut self, op: Op) -> Result<(), StoreError> {
        self.pending.push(op);
        if self.pending.len() >= BATCH {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StoreError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let ops = std::mem::take(&mut self.pending);
        self.idx.batch(|ix| {
            ops.iter().try_for_each(|op| match op {
                Op::Put(e) => ix.upsert(e),
                Op::Del(p) => ix.remove(p),
            })
        })
    }

    fn handle(&mut self, ev: Event) -> Result<(), StoreError> {
        match ev {
            Event::File {
                path,
                file,
                meta,
                last_checked_ns,
            } => self.file(path, file, meta, last_checked_ns)?,
            Event::Symlink(_) => self.summary.symlinks += 1,
            Event::Special(_) => self.summary.special += 1,
            Event::Mount(p) => {
                self.summary.mount += 1;
                self.excluded.insert(p.clone());
                self.report(ReportKind::Mount, p, None, None);
            }
            Event::SubExtant(p) => {
                self.summary.subextant += 1;
                self.excluded.insert(p.clone());
                self.report(ReportKind::SubExtant, p, None, None);
            }
            Event::Refused(p, e) => {
                if e.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) {
                    self.root_gone = true;
                } else {
                    self.root_refused = true;
                    self.summary.refused += 1;
                    self.report(ReportKind::Refused, p, None, Some(e.to_string()));
                }
            }
            Event::Unstable(p, e) => {
                self.unverified.insert(p.clone());
                self.push(Op::Del(p.clone()))?;
                self.summary.unstable += 1;
                self.report(ReportKind::Unstable, p, None, Some(e.to_string()));
            }
            Event::Error(p, e) => {
                self.unverified.insert(p.clone());
                self.summary.error += 1;
                self.report(ReportKind::Error, p, None, Some(e.to_string()));
            }
        }
        Ok(())
    }

    fn file(
        &mut self,
        path: Vec<u8>,
        file: File,
        meta: Meta,
        last_checked_ns: i64,
    ) -> Result<(), StoreError> {
        let stored = self.idx.get(&path)?;
        self.seen.insert(path.clone());
        if should_skip(stored.as_ref(), &meta, self.opts.full, self.opts.meta_cmp()) {
            self.summary.skipped += 1;
            return Ok(());
        }
        let hook = &mut *self.after_chunk;
        let mut hash = || hash_stable(&file, Alg::Sha256, &mut |n| hook(&path, n));
        // One retry: a single concurrent write is absorbed, a file that
        // keeps moving is not trusted.
        let hashed = match hash() {
            Err(HashError::Unstable) => hash(),
            r => r,
        };
        let (digest, current) = match hashed {
            Ok(r) => r,
            Err(HashError::Unstable) => {
                // Its content is known to differ from any stored digest, so
                // the entry must not be served.
                self.push(Op::Del(path.clone()))?;
                self.summary.unstable += 1;
                self.report(
                    ReportKind::Unstable,
                    path,
                    None,
                    Some(HashError::Unstable.to_string()),
                );
                return Ok(());
            }
            Err(HashError::Io(e)) => {
                // Content not known to have changed: the entry stays.
                self.summary.error += 1;
                self.report(ReportKind::Error, path, None, Some(e.to_string()));
                return Ok(());
            }
        };
        let entry = Entry {
            path: path.clone(),
            digest: digest.clone(),
            meta: current,
            last_checked_ns,
        };
        let stored_digest = stored.as_ref().map(|e| e.digest.clone());
        match classify(stored.as_ref(), &current, &digest, self.opts.meta_cmp()) {
            Status::New => {
                self.summary.new += 1;
                self.push(Op::Put(entry))?;
                self.report(ReportKind::New, path, None, None);
            }
            Status::Edited => {
                self.summary.edited += 1;
                self.push(Op::Put(entry))?;
                self.report(
                    ReportKind::Edited,
                    path,
                    stored_digest.map(|s| (s, digest)),
                    None,
                );
            }
            Status::Unchanged => {
                self.summary.unchanged += 1;
                self.push(Op::Put(entry))?;
            }
            Status::Violation => {
                let pair = stored_digest.map(|s| (s, digest));
                if self.opts.accept {
                    self.summary.accepted += 1;
                    self.push(Op::Put(entry))?;
                    self.report(ReportKind::Accepted, path, pair, None);
                } else {
                    self.summary.violation += 1;
                    self.report(ReportKind::Violation, path, pair, None);
                }
            }
        }
        Ok(())
    }
}
