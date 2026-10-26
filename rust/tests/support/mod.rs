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

/// Captured result of [`in_jail`].
pub struct JailOut {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

/// Runs shell `script` as (namespace) root in a private user+mount
/// namespace whose `/` is a fresh tmpfs holding only the `ext` binary and
/// its shared libraries. Mounting needs a namespace, and the store's
/// ancestor check needs every directory above it to be owned by us; inside
/// the jail `/` is ours, which is the only way both hold unprivileged.
///
/// The script sees `$J` (the jail's root, as seen from outside the chroot)
/// and `x ARGS...` (= `ext ARGS...` run inside the jail, where `$J/work` is
/// `/work`). Returns `None` when the namespace or its tools are unavailable,
/// so callers skip rather than fail.
pub fn in_jail(script: &str) -> Option<JailOut> {
    const SETUP: &str = r#"
J="$1"; BIN="$2"
mount -t tmpfs tmpfs "$J" || exit 77
cp "$BIN" "$J/ext" || exit 77
# Both the path ldd prints and where a symlink there really points.
for lib in $(ldd "$BIN" 2>/dev/null | grep -o '/[^ ]*'); do
  for f in "$lib" "$(readlink -f "$lib")"; do
    d=$(dirname "$f"); [ -d "$d" ] || continue
    mkdir -p "$J$d" && mount --bind "$d" "$J$d" || exit 77
  done
done
mkdir "$J/work"
x() { chroot "$J" /ext "$@"; }
"#;
    let (_t, dir) = canon_tmp();
    let mount_point = dir.join("jail");
    fs::create_dir(&mount_point).ok()?;
    let o = std::process::Command::new("unshare")
        .args(["-Urm", "sh", "-c"])
        .arg(format!("{SETUP}\n{script}"))
        .arg("sh")
        .arg(&mount_point)
        .arg(env!("CARGO_BIN_EXE_ext"))
        .env_remove("EXTANT_DIR")
        .output()
        .ok()?;
    let code = o.status.code()?;
    if code == 77 {
        return None;
    }
    Some(JailOut {
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        code,
    })
}
