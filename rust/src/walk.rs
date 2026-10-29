//! fd-relative tree walk that never follows symlinks or opens specials.

use crate::hash::meta_of;
use crate::index::{Meta, RootId};
use crate::registry::RegPath;
use rustix::fs::{
    fstat, fstatvfs, makedev, openat, openat2, statx, AtFlags, Dir, FileType, Mode, OFlags,
    ResolveFlags, Statx, StatxFlags, CWD,
};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;
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
    /// The entry changed type or identity between the metadata read and the
    /// open: known to be moving, so not merely unreadable.
    Unstable(Vec<u8>, io::Error),
}

const STAT_MASK: StatxFlags = StatxFlags::TYPE
    .union(StatxFlags::MODE)
    .union(StatxFlags::UID)
    .union(StatxFlags::INO)
    .union(StatxFlags::SIZE)
    .union(StatxFlags::MTIME)
    .union(StatxFlags::CTIME)
    .union(StatxFlags::MNT_ID);

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::DIRECTORY);

static NO_MNT_ID: Once = Once::new();

/// A directory held open while any of its children are still to be visited.
struct DirHandle {
    fd: OwnedFd,
    path: Vec<u8>,
}

/// A subdirectory found while listing its parent, opened only when popped.
/// Sharing the parent handle keeps open descriptors proportional to the
/// directories that still have unvisited children, not to tree depth.
struct Pending {
    parent: Rc<DirHandle>,
    name: CString,
    id: (u64, u64),
}

struct Ctx<'a> {
    store_id: (u64, u64),
    root_mnt: u64,
    root_uid: u32,
    /// Kernel without `STATX_MNT_ID`: mount identity degrades to `st_dev`.
    /// Wrong on btrfs subvolumes, hence only a fallback.
    use_dev: bool,
    stack: Vec<Pending>,
    /// Paths of other registered roots: each is walked by its own scan only.
    skip: &'a dyn Fn(&[u8]) -> bool,
    before_open: &'a mut dyn FnMut(&[u8]),
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

fn changed(what: &str) -> io::Error {
    io::Error::other(format!(
        "{what} changed type or identity while being opened"
    ))
}

/// The filesystem identity `walk` would record for `root` right now.
pub fn root_id(root: &RegPath) -> io::Result<RootId> {
    let fd = openat2(
        CWD,
        root.as_bytes(),
        DIR_FLAGS,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    Ok(RootId(fstatvfs(&fd)?.f_fsid))
}

/// Every descent is relative to a held descriptor, so no component can be
/// swapped for a symlink after it was checked.
pub fn walk(root: &RegPath, store_id: (u64, u64), visit: &mut dyn FnMut(Event)) {
    walk_hooked(root, store_id, &mut |_| {}, visit)
}

/// As [`walk`], but `before_open(path)` runs for each regular file and
/// directory after its metadata is read and before it is opened, so a test
/// can swap the entry in that window.
pub fn walk_hooked(
    root: &RegPath,
    store_id: (u64, u64),
    before_open: &mut dyn FnMut(&[u8]),
    visit: &mut dyn FnMut(Event),
) {
    walk_checked(
        root,
        store_id,
        &mut |_| Ok(()),
        &|_| false,
        before_open,
        visit,
    )
}

/// As [`walk_hooked`], and `check` sees the root's filesystem identity once
/// the root is open; an `Err` refuses the root before anything is listed.
pub(crate) fn walk_checked(
    root: &RegPath,
    store_id: (u64, u64),
    check: &mut dyn FnMut(RootId) -> io::Result<()>,
    skip: &dyn Fn(&[u8]) -> bool,
    before_open: &mut dyn FnMut(&[u8]),
    visit: &mut dyn FnMut(Event),
) {
    let path = root.as_bytes().to_vec();
    let fd = match openat2(
        CWD,
        root.as_bytes(),
        DIR_FLAGS,
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
    let root_mnt = if use_dev { dev_of(&st) } else { st.stx_mnt_id };
    let id = match fstatvfs(&fd) {
        Ok(v) => RootId(v.f_fsid),
        Err(e) => return visit(Event::Error(path, e.into())),
    };
    if let Err(e) = check(id) {
        return visit(Event::Refused(path, e));
    }
    let mut ctx = Ctx {
        store_id,
        root_mnt,
        root_uid: st.stx_uid,
        use_dev,
        stack: Vec::new(),
        skip,
        before_open,
        visit,
    };
    list_dir(&mut ctx, Rc::new(DirHandle { fd, path }), true);
    // Explicit stack: depth costs heap, never call-stack or one fd per level.
    while let Some(p) = ctx.stack.pop() {
        let path = child_path(&p.parent.path, p.name.to_bytes());
        (ctx.before_open)(&path);
        let fd = match openat(&p.parent.fd, &p.name, DIR_FLAGS, Mode::empty()) {
            Ok(fd) => fd,
            // O_NOFOLLOW|O_DIRECTORY on a name swapped for a symlink or a
            // file fails with ELOOP or ENOTDIR.
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                (ctx.visit)(Event::Unstable(path, changed("directory")));
                continue;
            }
            Err(e) => {
                (ctx.visit)(Event::Error(path, e.into()));
                continue;
            }
        };
        match fstat(&fd) {
            Ok(f) if (f.st_dev, f.st_ino) == p.id => {
                // Release the parent before descending; if this was its last
                // pending child, its descriptor closes here.
                drop(p);
                list_dir(&mut ctx, Rc::new(DirHandle { fd, path }), false);
            }
            Ok(_) => (ctx.visit)(Event::Unstable(path, changed("directory"))),
            Err(e) => (ctx.visit)(Event::Error(path, e.into())),
        }
    }
}

/// A `.ext` directory makes its parent a sub-extant only if it is a real
/// store: registry, index.db and lock present as regular files, owned by the
/// root's owner or by root, and not group/other-writable. Any other `.ext`
/// is ordinary content, so planting one cannot hide a subtree.
fn is_real_store(ctx: &Ctx<'_>, parent: &OwnedFd, ext: &Statx) -> bool {
    let trusted =
        |st: &Statx| (st.stx_uid == 0 || st.stx_uid == ctx.root_uid) && st.stx_mode & 0o022 == 0;
    if !trusted(ext) {
        return false;
    }
    let Ok(dir) = openat(parent, ".ext", DIR_FLAGS, Mode::empty()) else {
        return false;
    };
    ["registry", "index.db", "lock"].iter().all(|f| {
        statx(
            &dir,
            *f,
            AtFlags::SYMLINK_NOFOLLOW,
            StatxFlags::TYPE | StatxFlags::MODE | StatxFlags::UID,
        )
        .is_ok_and(|st| is_type(&st, FileType::RegularFile) && trusted(&st))
    })
}

/// A registered root is walked even if it holds a store of its own: the
/// registration is what lets a parent hash a sub-extant's files itself.
fn list_dir(ctx: &mut Ctx<'_>, dir: Rc<DirHandle>, is_root: bool) {
    match statx(
        &dir.fd,
        ".ext",
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::TYPE | StatxFlags::MODE | StatxFlags::UID | StatxFlags::INO,
    ) {
        Ok(st)
            if !is_root
                && is_type(&st, FileType::Directory)
                && (dev_of(&st), st.stx_ino) != ctx.store_id
                && is_real_store(ctx, &dir.fd, &st) =>
        {
            return (ctx.visit)(Event::SubExtant(dir.path.clone()));
        }
        Ok(_) => {}
        Err(rustix::io::Errno::NOENT) => {}
        // Not knowing whether this is a sub-extant means not walking it.
        Err(e) => return (ctx.visit)(Event::Error(dir.path.clone(), e.into())),
    }
    let mut listing = match Dir::read_from(&dir.fd) {
        Ok(d) => d,
        Err(e) => return (ctx.visit)(Event::Error(dir.path.clone(), e.into())),
    };
    while let Some(ent) = listing.read() {
        let ent = match ent {
            Ok(ent) => ent,
            // A failed listing cannot be resumed; the directory as a whole
            // is unverified.
            Err(e) => return (ctx.visit)(Event::Error(dir.path.clone(), e.into())),
        };
        let name: &CStr = ent.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        visit_child(ctx, &dir, name);
    }
}

fn visit_child(ctx: &mut Ctx<'_>, dir: &Rc<DirHandle>, name: &CStr) {
    // Sampled before the metadata read (PR #12): anything modified after this
    // instant is at worst reported racy, never trusted.
    let last_checked_ns = now_ns();
    let path = child_path(&dir.path, name.to_bytes());
    let st = match statx(&dir.fd, name, AtFlags::SYMLINK_NOFOLLOW, STAT_MASK) {
        Ok(st) => st,
        // Vanished since the listing: simply absent from this scan.
        Err(rustix::io::Errno::NOENT) => return,
        Err(e) => return (ctx.visit)(Event::Error(path, e.into())),
    };
    let id = (dev_of(&st), st.stx_ino);
    match FileType::from_raw_mode(st.stx_mode.into()) {
        FileType::Symlink => (ctx.visit)(Event::Symlink(path)),
        FileType::Directory => {
            // A store is never content, whether it is the one in use or a
            // sub-extant's that a registered root hashes around.
            if id == ctx.store_id
                || (name.to_bytes() == b".ext" && is_real_store(ctx, &dir.fd, &st))
                || (ctx.skip)(&path)
            {
                return;
            }
            let child_mnt = if ctx.use_dev { id.0 } else { st.stx_mnt_id };
            if crosses_mount(ctx.root_mnt, child_mnt) {
                return (ctx.visit)(Event::Mount(path));
            }
            ctx.stack.push(Pending {
                parent: Rc::clone(dir),
                name: name.to_owned(),
                id,
            });
        }
        FileType::RegularFile => {
            (ctx.before_open)(&path);
            // NONBLOCK: should the name be swapped for a FIFO after the
            // check above, the open still cannot hang.
            let fd = match openat(
                &dir.fd,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                // A name swapped for a symlink fails O_NOFOLLOW with ELOOP.
                Err(rustix::io::Errno::LOOP) => {
                    return (ctx.visit)(Event::Unstable(path, changed("file")))
                }
                Err(e) => return (ctx.visit)(Event::Error(path, e.into())),
            };
            let file = File::from(fd);
            let md = match file.metadata() {
                Ok(md) => md,
                Err(e) => return (ctx.visit)(Event::Error(path, e)),
            };
            if !md.file_type().is_file() || (md.dev(), md.ino()) != id {
                return (ctx.visit)(Event::Unstable(path, changed("file")));
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
