#![allow(dead_code)]
use ext::registry::RegPath;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Hand-built flat store (dir + registry + index.db + lock), independent of
/// `Store::init_bare`, so resolution tests fail only at the code under test.
pub fn mk_store(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    for f in ["registry", "index.db", "lock"] {
        let p = dir.join(f);
        fs::write(&p, b"").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

pub fn rp(b: &[u8]) -> RegPath {
    RegPath::from_bytes(b).expect("test path is valid")
}

pub fn euid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    // A file we just created is owned by the effective user.
    let d = tempfile::tempdir().unwrap();
    fs::metadata(d.path()).unwrap().uid()
}
