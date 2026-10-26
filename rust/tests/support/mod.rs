#![allow(dead_code)]
//! Step-3 helpers: canonical temp trees, a registered bare store, clocks.

use ext::registry::RegPath;
use ext::store::Store;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Temp dir whose path contains no symlink (openat2 NO_SYMLINKS would
/// otherwise refuse every root for reasons unrelated to the test).
pub fn canon_tmp() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = fs::canonicalize(t.path()).unwrap();
    (t, p)
}

pub fn rp(p: &Path) -> RegPath {
    RegPath::from_bytes(p.as_os_str().as_bytes()).expect("valid root")
}

pub fn b(p: &Path) -> Vec<u8> {
    p.as_os_str().as_bytes().to_vec()
}

pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64
}

pub fn time_from_ns(ns: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(ns as u64)
}

/// A bare store in `<base>/store` whose registry holds exactly `roots`.
pub fn store_with_roots(base: &Path, roots: &[&Path]) -> Store {
    let st = Store::init_bare(&base.join("store")).unwrap();
    let lock = st.lock().unwrap();
    let rs: Vec<RegPath> = roots.iter().map(|r| rp(r)).collect();
    st.edit_registry(&lock, |v| *v = rs).unwrap();
    drop(lock);
    st
}

pub fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}
