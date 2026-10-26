//! Merge-gate hardening for step 2: trust boundary (ancestor check, path
//! swap), atomic init, and mutation-gap closers.

mod common;
use common::{mk_store, rp};
use ext::digest::{Alg, Digest};
use ext::index::{Entry, Index, Meta};
use ext::store::{judge_ancestor, locate, Source, Store, StoreError};
use std::fs;
use std::io;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

fn chmod(p: &Path, mode: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

fn is_unsafe(r: &Result<Store, StoreError>, p: &Path) -> bool {
    matches!(r, Err(StoreError::UnsafeAncestor(q)) if q == p)
}

/// A store `<tmp>/p/s` created while `p` is safe; the caller may then loosen `p`.
fn store_under_parent() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let parent = t.path().join("p");
    fs::create_dir(&parent).unwrap();
    let dir = parent.join("s");
    Store::init_bare(&dir).unwrap();
    (t, parent, dir)
}

// ---- ancestor check (F1) ----

#[test]
fn ancestor_policy_on_real_dirs() {
    for mode in [0o770, 0o707, 0o777, 0o720] {
        let (_t, parent, dir) = store_under_parent();
        chmod(&parent, mode);
        assert!(
            is_unsafe(&Store::open(&dir), &parent),
            "parent mode {mode:o}"
        );
    }
    for mode in [0o1777, 0o1770, 0o1707] {
        let (_t, parent, dir) = store_under_parent();
        chmod(&parent, mode);
        Store::open(&dir).unwrap_or_else(|e| panic!("sticky {mode:o}: {e:?}"));
    }
    // Every level of the path is checked, not only the parent.
    let t = tempfile::tempdir().unwrap();
    let g = t.path().join("g");
    let p = g.join("p");
    fs::create_dir_all(&p).unwrap();
    let dir = p.join("s");
    Store::init_bare(&dir).unwrap();
    chmod(&g, 0o777);
    assert!(is_unsafe(&Store::open(&dir), &g));
    chmod(&g, 0o755);
    Store::open(&dir).unwrap();
}

#[test]
fn judge_ancestor_on_constructed_stat() {
    let p = Path::new("/a");
    let dir = 0o040000;
    for (uid, mode, euid) in [
        (0, dir | 0o755, 1000),
        (1000, dir | 0o755, 1000),
        (0, dir | 0o1777, 1000),
        (1000, dir | 0o1770, 1000),
        (0, dir | 0o755, 0),
    ] {
        assert!(
            judge_ancestor(uid, mode, euid, p).is_ok(),
            "{uid} {mode:o} {euid}"
        );
    }
    for (uid, mode, euid) in [
        (1234, dir | 0o755, 1000),  // foreign owner
        (1234, dir | 0o1777, 1000), // sticky does not excuse a foreign owner
        (0, dir | 0o777, 1000),
        (1000, dir | 0o775, 1000),
        (1000, dir | 0o757, 1000),
        (0, dir | 0o770, 0),
    ] {
        assert!(
            matches!(judge_ancestor(uid, mode, euid, p), Err(StoreError::UnsafeAncestor(q)) if q == p),
            "{uid} {mode:o} {euid}"
        );
    }
}

// ---- path swap (F2) ----

fn entry(p: &[u8]) -> Entry {
    Entry {
        path: p.to_vec(),
        digest: Digest::compute(Alg::Sha256, p),
        meta: Meta {
            size: 1,
            mtime_ns: 1,
            ctime_ns: 1,
            dev: 1,
            ino: 1,
        },
        last_checked_ns: 1,
    }
}

/// Builds a valid v1 decoy store at `at` (index.db mode `db_mode`).
fn decoy(at: &Path, db_mode: u32) {
    let donor = Store::init_bare(&at.with_file_name("donor")).unwrap();
    let ix = Index::open(&donor).unwrap();
    ix.upsert(&entry(b"/decoy")).unwrap();
    drop(ix);
    let from = at.with_file_name("donor");
    fs::create_dir(at).unwrap();
    chmod(at, 0o700);
    for f in ["registry", "index.db", "lock"] {
        fs::copy(from.join(f), at.join(f)).unwrap();
        chmod(&at.join(f), 0o600);
    }
    chmod(&at.join("index.db"), db_mode);
}

/// Swapping the store path after `Store::open` must not redirect the index
/// to a decoy database (modifying it) nor create a database in a bare
/// swapped-in directory.
#[test]
fn index_open_after_swap() {
    for decoy_db in [true, false] {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("s");
        Store::init_bare(&dir).unwrap();
        let st = Store::open(&dir).unwrap();
        fs::rename(&dir, t.path().join("old")).unwrap();
        if decoy_db {
            decoy(&dir, 0o666);
        } else {
            fs::create_dir(&dir).unwrap();
            chmod(&dir, 0o700);
        }
        let before = decoy_db.then(|| fs::read(dir.join("index.db")).unwrap());
        let listed = listing(&dir);
        assert!(
            Index::open(&st).is_err(),
            "decoy_db={decoy_db}: opened the swapped-in directory"
        );
        assert_eq!(listing(&dir), listed, "decoy_db={decoy_db}: wal/shm/db created");
        if let Some(before) = before {
            assert_eq!(fs::read(dir.join("index.db")).unwrap(), before, "decoy modified");
        }
    }
}

// ---- atomic init (F1 part 3) ----

fn injected() -> io::Result<()> {
    Err(io::Error::other("injected"))
}

#[test]
fn init_bare_failure_before_publish_leaves_nothing() {
    let t = tempfile::tempdir().unwrap();
    let parent = fs::canonicalize(t.path()).unwrap();
    let dir = parent.join("s");
    let before = listing(&parent);
    let mut seen = None;
    let r = Store::init_bare_with(&dir, &mut |tmp| {
        seen = Some((
            tmp.to_path_buf(),
            dir.exists(),
            tmp.join("registry").is_file(),
        ));
        injected()
    });
    assert!(matches!(r, Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::Other));
    let (tmp, target_visible, built) = seen.expect("hook ran");
    assert!(!target_visible, "target visible before publish");
    assert!(built, "hook must run after the store is fully built");
    assert_eq!(
        tmp.parent(),
        Some(parent.as_path()),
        "temp must be a sibling"
    );
    assert!(!tmp.exists(), "temp left behind");
    assert_eq!(listing(&parent), before);
    Store::init_bare(&dir).expect("retry after failure succeeds");
}

#[test]
fn init_extant_never_publishes_a_store_without_its_root() {
    let t = tempfile::tempdir().unwrap();
    let dir = fs::canonicalize(t.path()).unwrap();
    let before = listing(&dir);
    let mut seen = None;
    let r = Store::init_extant_with(&dir, &mut |tmp| {
        let reg = fs::read(tmp.join("registry")).unwrap();
        seen = Some((tmp.to_path_buf(), dir.join(".ext").exists(), reg));
        injected()
    });
    assert!(r.is_err());
    let (tmp, ext_visible, reg) = seen.expect("hook ran");
    assert!(!ext_visible, ".ext visible before publish");
    assert_eq!(
        ext::registry::parse(&reg).unwrap(),
        vec![rp(dir.as_os_str().as_encoded_bytes())],
        "temp store must already hold its root"
    );
    assert!(!tmp.exists());
    assert_eq!(listing(&dir), before, "residue after failed init");
    let st = Store::init_extant(&dir).expect("retry succeeds");
    assert_eq!(st.registry().unwrap().len(), 1);
}

// ---- mutation-gap closers ----

#[test]
fn edit_registry_on_corrupt_registry_errors_and_keeps_bytes() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    let bad = b"/ok\nrelative\n/also\n".to_vec();
    fs::write(dir.join("registry"), &bad).unwrap();
    let g = st.lock().unwrap();
    let r = st.edit_registry(&g, |v| v.push(rp(b"/new")));
    assert!(
        matches!(r, Err(StoreError::Registry { line: 2, .. })),
        "{r:?}"
    );
    assert_eq!(fs::read(dir.join("registry")).unwrap(), bad);
    assert_eq!(listing(&dir), ["index.db", "lock", "registry"]);
}

#[test]
fn init_extant_registers_realpath_for_symlink_and_dotdot() {
    let t = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(t.path()).unwrap();
    let real = base.join("real");
    fs::create_dir(&real).unwrap();
    symlink(&real, base.join("link")).unwrap();
    let st = Store::init_extant(&base.join("link")).unwrap();
    assert_eq!(
        st.registry().unwrap(),
        vec![rp(real.as_os_str().as_encoded_bytes())]
    );
    assert!(real.join(".ext/registry").is_file());

    let r2 = base.join("real2");
    fs::create_dir_all(r2.join("sub")).unwrap();
    let st = Store::init_extant(&r2.join("sub/..")).unwrap();
    assert_eq!(
        st.registry().unwrap(),
        vec![rp(r2.as_os_str().as_encoded_bytes())]
    );
}

#[test]
fn lock_refuses_a_symlinked_lock_file() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    let victim = t.path().join("victim");
    fs::write(&victim, b"keep").unwrap();
    fs::remove_file(dir.join("lock")).unwrap();
    symlink(&victim, dir.join("lock")).unwrap();
    assert!(st.lock().is_err());
    assert_eq!(fs::read(&victim).unwrap(), b"keep");
}

#[test]
fn open_refuses_symlinked_or_non_regular_store_files() {
    for f in ["registry", "index.db", "lock"] {
        for kind in ["symlink", "dir"] {
            let t = tempfile::tempdir().unwrap();
            let dir = t.path().join("s");
            Store::init_bare(&dir).unwrap();
            fs::remove_file(dir.join(f)).unwrap();
            if kind == "symlink" {
                let target = t.path().join("target");
                fs::write(&target, b"").unwrap();
                chmod(&target, 0o600);
                symlink(&target, dir.join(f)).unwrap();
            } else {
                fs::create_dir(dir.join(f)).unwrap();
                chmod(&dir.join(f), 0o700);
            }
            let r = Store::open(&dir);
            assert!(
                matches!(r, Err(StoreError::NotAStore(_))),
                "{f} as {kind}: {:?}",
                r.err()
            );
        }
    }
    // A directory without its registry is not a store.
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    Store::init_bare(&dir).unwrap();
    fs::remove_file(dir.join("registry")).unwrap();
    assert!(matches!(Store::open(&dir), Err(StoreError::NotAStore(_))));
    // The store directory itself is opened O_NOFOLLOW.
    let t = tempfile::tempdir().unwrap();
    let real = t.path().join("real");
    Store::init_bare(&real).unwrap();
    let link = t.path().join("link");
    symlink(&real, &link).unwrap();
    assert!(Store::open(&link).is_err());
}

#[test]
fn locate_prefers_p_over_p_dot_ext_when_both_are_stores() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("p");
    mk_store(&p);
    mk_store(&p.join(".ext"));
    let got = locate(Some(&p), None, &t.path().join("nodef"), t.path()).unwrap();
    assert_eq!(got, (p, Source::Flag));
}

#[test]
fn write_lock_of_another_store_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let a = Store::init_bare(&t.path().join("a")).unwrap();
    let b = Store::init_bare(&t.path().join("b")).unwrap();
    let la = a.lock().unwrap();
    let r = b.edit_registry(&la, |v| v.push(rp(b"/x")));
    assert!(r.is_err(), "edited store b under store a's lock");
    assert!(b.registry().unwrap().is_empty());
}

#[test]
fn stale_registry_tmp_is_cleared_and_never_followed() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    fs::write(dir.join("registry.tmp"), b"garbage from a crashed writer").unwrap();
    let g = st.lock().unwrap();
    st.edit_registry(&g, |v| v.push(rp(b"/a"))).unwrap();
    assert_eq!(st.registry().unwrap(), vec![rp(b"/a")]);
    assert_eq!(listing(&dir), ["index.db", "lock", "registry"]);

    let victim = t.path().join("victim");
    fs::write(&victim, b"keep").unwrap();
    symlink(&victim, dir.join("registry.tmp")).unwrap();
    st.edit_registry(&g, |v| v.push(rp(b"/b"))).unwrap();
    assert_eq!(
        fs::read(&victim).unwrap(),
        b"keep",
        "wrote through a symlinked temp"
    );
    assert_eq!(st.registry().unwrap().len(), 2);
    assert_eq!(listing(&dir), ["index.db", "lock", "registry"]);
}

// ---- re-gate additions ----

/// init must apply the same ancestor rule as open, and leave nothing behind;
/// otherwise it produces a store that cannot be opened.
#[test]
fn init_under_writable_nonsticky_parent_is_refused_and_leaves_nothing() {
    let t = tempfile::tempdir().unwrap();
    let parent = fs::canonicalize(t.path()).unwrap().join("p");
    fs::create_dir(&parent).unwrap();
    chmod(&parent, 0o777);
    let r = Store::init_bare(&parent.join("s"));
    assert!(is_unsafe(&r, &parent), "init_bare: {:?}", r.err());
    assert!(
        listing(&parent).is_empty(),
        "init_bare left {:?}",
        listing(&parent)
    );
    let r = Store::init_extant(&parent);
    assert!(is_unsafe(&r, &parent), "init_extant: {:?}", r.err());
    assert!(
        listing(&parent).is_empty(),
        "init_extant left {:?}",
        listing(&parent)
    );
}

/// The ancestor walk is over the canonical path: a symlink in the given
/// path must not hide an unsafe directory on the real path.
#[test]
fn ancestor_check_uses_the_canonical_path() {
    let t = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(t.path()).unwrap();
    let a = base.join("a");
    let b = a.join("b");
    fs::create_dir_all(&b).unwrap();
    chmod(&b, 0o700);
    Store::init_bare(&b.join("s")).unwrap();
    chmod(&a, 0o777);
    let trusted = base.join("trusted");
    fs::create_dir(&trusted).unwrap();
    symlink(&b, trusted.join("link")).unwrap();
    assert!(is_unsafe(&Store::open(&trusted.join("link/s")), &a));
}

