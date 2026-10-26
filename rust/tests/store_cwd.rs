//! Kept in its own binary: it changes the process working directory, which
//! would race with every other test in a shared binary.

use ext::store::Store;
use std::fs;
use std::path::Path;

#[test]
fn init_extant_relative_dir_registers_realpath() {
    let t = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(t.path()).unwrap();
    fs::create_dir(base.join("sub")).unwrap();
    std::env::set_current_dir(&base).unwrap();
    let st = Store::init_extant(Path::new("sub")).unwrap();
    let reg = st.registry().unwrap();
    assert_eq!(reg.len(), 1);
    assert_eq!(
        reg[0].as_bytes(),
        base.join("sub").as_os_str().as_encoded_bytes()
    );
    assert!(base.join("sub/.ext/registry").is_file());
}
