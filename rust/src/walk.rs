//! fd-relative tree walk that never follows symlinks or opens specials.

use crate::hash::meta_of;
use crate::index::Meta;
use crate::registry::RegPath;
use rustix::fs::{
    fstat, makedev, openat, openat2, statx, AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags,
    Statx, StatxFlags, CWD,
};
use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Carried by an `Event::Error` when the entry changed type or identity
/// between the metadata read and the open: the file is known to be moving,
/// so `scan` treats it as unstable rather than merely unreadable.
#[derive(Debug)]
pub struct ChangedDuringWalk;

impl std::fmt::Display for ChangedDuringWalk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("entry changed type or identity while it was being opened")
    }
}

impl std::error::Error for ChangedDuringWalk {}

impl ChangedDuringWalk {
    pub fn is(e: &io::Error) -> bool {
        e.get_ref().is_some_and(|i| i.is::<ChangedDuringWalk>())
    }
}

const STAT_MASK: StatxFlags = StatxFlags::TYPE
    .union(StatxFlags::MODE)
    .union(StatxFlags::INO)
    .union(StatxFlags::SIZE)
    .union(StatxFlags::MTIME)
    .union(StatxFlags::CTIME)
    .union(StatxFlags::MNT_ID);

static NO_MNT_ID: Once = Once::new();

struct Ctx<'a> {
    store_id: (u64, u64),
    root_mnt: u64,
    /// Kernel without `STATX_MNT_ID`: mount identity degrades to `st_dev`.
    /// Wrong on btrfs subvolumes, hence only a fallback.
    use_dev: bool,
    visit: &'a mut dyn FnMut(Event),
}

pub(crate) fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
        // An unrepresentable clock must err toward re-hashing: MAX makes
        // every stored timestamp racy.
        .unwrap_or(i64::MAX)
}

fn dev_of(st: &Statx) -> u64 {
    makedev(st.stx_dev_major, st.stx_dev_minor)
}

fn mount_key(ctx: &Ctx<'_>, st: &Statx) -> u64 {
    if ctx.use_dev {
        dev_of(st)
    } else {
        st.stx_mnt_id
    }
}

fn is_type(st: &Statx, t: FileType) -> bool {
    FileType::from_raw_mode(st.stx_mode.into()) == t
}

fn child_path(parent: &[u8], name: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(parent.len() + 1 + name.len());
    p.extend_from_slice(parent);
    if parent != b"/" {
        p.push(b'/');
    }
    p.extend_from_slice(name);
    p
}

/// Every descent is relative to a held descriptor, so no component can be
/// swapped for a symlink after it was checked.
pub fn walk(root: &RegPath, store_id: (u64, u64), visit: &mut dyn FnMut(Event)) {
    let path = root.as_bytes().to_vec();
    let fd = match openat2(
        CWD,
        root.as_bytes(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => fd,
        Err(e) => return visit(Event::Refused(path, e.into())),
    };
    let st = match statx(
        &fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
        STAT_MASK,
    ) {
        Ok(st) => st,
        Err(e) => return visit(Event::Error(path, e.into())),
    };
    let use_dev = st.stx_mask & StatxFlags::MNT_ID.bits() == 0;
    if use_dev {
        NO_MNT_ID.call_once(|| {
            eprintln!("warning: kernel lacks STATX_MNT_ID; mount boundaries compared by st_dev");
        });
    }
    let mut ctx = Ctx {
        store_id,
        root_mnt: 0,
        use_dev,
        visit,
    };
    ctx.root_mnt = mount_key(&ctx, &st);
    walk_dir(&mut ctx, fd, path);
}

fn walk_dir(ctx: &mut Ctx<'_>, fd: OwnedFd, path: Vec<u8>) {
    // A `.ext` directory that is not our own store makes this a sub-extant
    // with its own index; its content never enters ours.
    match statx(
        &fd,
        ".ext",
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::TYPE | StatxFlags::INO,
    ) {
        Ok(st)
            if is_type(&st, FileType::Directory) && (dev_of(&st), st.stx_ino) != ctx.store_id =>
        {
            return (ctx.visit)(Event::SubExtant(path));
        }
        Ok(_) => {}
        Err(rustix::io::Errno::NOENT) => {}
        // Not knowing whether this is a sub-extant means not walking it.
        Err(e) => return (ctx.visit)(Event::Error(path, e.into())),
    }
    let mut dir = match Dir::read_from(&fd) {
        Ok(d) => d,
        Err(e) => return (ctx.visit)(Event::Error(path, e.into())),
    };
    while let Some(ent) = dir.read() {
        let ent = match ent {
            Ok(ent) => ent,
            // A failed listing cannot be resumed; the directory as a whole
            // is unverified.
            Err(e) => return (ctx.visit)(Event::Error(path, e.into())),
        };
        let name: &CStr = ent.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        walk_child(ctx, &fd, &path, name);
    }
}

fn walk_child(ctx: &mut Ctx<'_>, dirfd: &OwnedFd, parent: &[u8], name: &CStr) {
    // Sampled before the metadata read (PR #12): anything modified after this
    // instant is at worst reported racy, never trusted.
    let last_checked_ns = now_ns();
    let path = child_path(parent, name.to_bytes());
    let st = match statx(dirfd, name, AtFlags::SYMLINK_NOFOLLOW, STAT_MASK) {
        Ok(st) => st,
        // Vanished since the listing: simply absent from this scan.
        Err(rustix::io::Errno::NOENT) => return,
        Err(e) => return (ctx.visit)(Event::Error(path, e.into())),
    };
    match FileType::from_raw_mode(st.stx_mode.into()) {
        FileType::Symlink => (ctx.visit)(Event::Symlink(path)),
        FileType::Directory => {
            if (dev_of(&st), st.stx_ino) == ctx.store_id {
                return;
            }
            if crosses_mount(ctx.root_mnt, mount_key(ctx, &st)) {
                return (ctx.visit)(Event::Mount(path));
            }
            let fd = match openat(
                dirfd,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(e) => return (ctx.visit)(Event::Error(path, e.into())),
            };
            match fstat(&fd) {
                Ok(f) if (f.st_dev, f.st_ino) == (dev_of(&st), st.stx_ino) => {
                    walk_dir(ctx, fd, path)
                }
                Ok(_) => (ctx.visit)(Event::Error(path, io::Error::other(ChangedDuringWalk))),
                Err(e) => (ctx.visit)(Event::Error(path, e.into())),
            }
        }
        FileType::RegularFile => {
            // NONBLOCK: should the name be swapped for a FIFO after the
            // check above, the open still cannot hang.
            let fd = match openat(
                dirfd,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(e) => return (ctx.visit)(Event::Error(path, e.into())),
            };
            let file = File::from(fd);
            let md = match file.metadata() {
                Ok(md) => md,
                Err(e) => return (ctx.visit)(Event::Error(path, e)),
            };
            if !md.file_type().is_file() || std::os::unix::fs::MetadataExt::ino(&md) != st.stx_ino {
                return (ctx.visit)(Event::Error(path, io::Error::other(ChangedDuringWalk)));
            }
            (ctx.visit)(Event::File {
                path,
                file,
                meta: meta_of(&md),
                last_checked_ns,
            });
        }
        // Never opened: opening a device or FIFO can block or have effects.
        _ => (ctx.visit)(Event::Special(path)),
    }
}

/// Pure so the mount rule is testable without privilege.
pub fn crosses_mount(root_mnt: u64, child_mnt: u64) -> bool {
    root_mnt != child_mnt
}
