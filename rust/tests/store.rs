//! Acceptance tests for plan step 2: store resolution, ownership, locking,
//! registry editing (plan sections 1 "Store"/"Registry" and 3).

mod common;
use common::{euid, mk_store, rp};
use ext::store::{locate, Source, Store, StoreError};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug)]
enum Arg {
    None,
    Store,     // <p> is a store
    ViaDotExt, // <p>/.ext is a store
    Missing,   // <p> does not exist
    NotAStore, // <p> exists, neither <p> nor <p>/.ext is a store
    Empty,     // env only: set to ""
}

/// Reference model of the plan's resolution order; the implementation under
/// test must agree with it on every combination.
fn expected(
    flag: Arg,
    env: Arg,
    default_present: bool,
    cwd_present: bool,
    paths: &Paths,
) -> Result<(PathBuf, Source), &'static str> {
    let explicit =
        |a: Arg, p: &Path, s: Source| -> Option<Result<(PathBuf, Source), &'static str>> {
            match a {
                Arg::None | Arg::Empty => None,
                Arg::Store => Some(Ok((p.to_path_buf(), s))),
                Arg::ViaDotExt => Some(Ok((p.join(".ext"), s))),
                Arg::Missing => Some(Err("ExplicitMissing")),
                Arg::NotAStore => Some(Err("NotAStore")),
            }
        };
    if let Some(r) = explicit(flag, &paths.flag, Source::Flag) {
        return r;
    }
    if let Some(r) = explicit(env, &paths.env, Source::Env) {
        return r;
    }
    if default_present {
        return Ok((paths.default.clone(), Source::Default));
    }
    if cwd_present {
        return Ok((paths.cwd.join(".ext"), Source::Cwd));
    }
    Err("NoStore")
}

struct Paths {
    flag: PathBuf,
    env: PathBuf,
    default: PathBuf,
    cwd: PathBuf,
}

fn materialise(a: Arg, p: &Path) {
    match a {
        Arg::None | Arg::Empty | Arg::Missing => {}
        Arg::Store => mk_store(p),
        Arg::ViaDotExt => mk_store(&p.join(".ext")),
        Arg::NotAStore => fs::create_dir_all(p).unwrap(),
    }
}

fn classify(r: &Result<(PathBuf, Source), StoreError>) -> Result<(PathBuf, Source), &'static str> {
    match r {
        Ok(v) => Ok(v.clone()),
        Err(StoreError::ExplicitMissing(_)) => Err("ExplicitMissing"),
        Err(StoreError::NotAStore(_)) => Err("NotAStore"),
        Err(StoreError::NoStore) => Err("NoStore"),
        Err(e) => panic!("unexpected error variant from locate: {e:?}"),
    }
}

/// Plan §1 "Resolution order" and §3 locate tests: every combination of
/// flag/env/default/cwd presence.
#[test]
fn precedence_table_all_combinations() {
    let args = [
        Arg::None,
        Arg::Store,
        Arg::ViaDotExt,
        Arg::Missing,
        Arg::NotAStore,
    ];
    let env_args = [
        Arg::None,
        Arg::Empty,
        Arg::Store,
        Arg::ViaDotExt,
        Arg::Missing,
        Arg::NotAStore,
    ];
    let mut n = 0;
    for &flag in &args {
        for &env in &env_args {
            for default_present in [false, true] {
                for cwd_present in [false, true] {
                    let t = tempfile::tempdir().unwrap();
                    let paths = Paths {
                        flag: t.path().join("flag"),
                        env: t.path().join("env"),
                        default: t.path().join("default"),
                        cwd: t.path().join("cwd"),
                    };
                    fs::create_dir_all(&paths.cwd).unwrap();
                    materialise(flag, &paths.flag);
                    materialise(env, &paths.env);
                    if default_present {
                        mk_store(&paths.default);
                    }
                    if cwd_present {
                        mk_store(&paths.cwd.join(".ext"));
                    }
                    let flag_arg = (!matches!(flag, Arg::None)).then_some(paths.flag.as_path());
                    let env_os: Option<&OsStr> = match env {
                        Arg::None => None,
                        Arg::Empty => Some(OsStr::new("")),
                        _ => Some(paths.env.as_os_str()),
                    };
                    let got = locate(flag_arg, env_os, &paths.default, &paths.cwd);
                    let want = expected(flag, env, default_present, cwd_present, &paths);
                    assert_eq!(
                        classify(&got),
                        want,
                        "flag={flag:?} env={env:?} default={default_present} cwd={cwd_present}"
                    );
                    n += 1;
                }
            }
        }
    }
    assert_eq!(n, 5 * 6 * 2 * 2);
}

/// §1: Store::open("/") is Foreign for a non-root user.
#[test]
fn open_foreign_owned_store_refused() {
    if euid() == 0 {
        eprintln!("skipped: running as root, `/` is not foreign");
        return;
    }
    match Store::open(Path::new("/")) {
        Err(StoreError::Foreign { uid: 0, .. }) => {}
        Err(e) => panic!("expected Foreign{{uid:0}}, got {e:?}"),
        Ok(_) => panic!("opened a root-owned directory"),
    }
}

/// A foreign-owned registry/index.db/lock needs a second uid we cannot
/// create unprivileged, so the judgement is tested on raw stat values.
#[test]
fn judge_owner_mode_on_constructed_stat() {
    use ext::store::judge_owner_mode as j;
    let p = Path::new("/s/registry");
    assert!(j(1000, 0o100600, 1000, p).is_ok());
    assert!(j(1000, 0o040700, 1000, p).is_ok());
    assert!(j(1000, 0o100640, 1000, p).is_ok());
    assert!(matches!(
        j(0, 0o100600, 1000, p),
        Err(StoreError::Foreign { uid: 0, .. })
    ));
    assert!(matches!(
        j(1234, 0o100600, 1000, p),
        Err(StoreError::Foreign { uid: 1234, .. })
    ));
    for mode in [0o100620, 0o100602, 0o100666, 0o040770] {
        assert!(
            matches!(j(1000, mode, 1000, p), Err(StoreError::Writable(_))),
            "{mode:o}"
        );
    }
    // Foreign owner is reported before writability.
    assert!(matches!(
        j(0, 0o100777, 1000, p),
        Err(StoreError::Foreign { .. })
    ));
}

/// A store whose directory or any file is group/other-writable is refused.
#[test]
fn open_refuses_loose_modes() {
    for (target, modes) in [
        (None, vec![0o770, 0o707, 0o777, 0o720]),
        (Some("registry"), vec![0o664, 0o606]),
        (Some("index.db"), vec![0o664, 0o606]),
        (Some("lock"), vec![0o664, 0o606]),
    ] {
        for mode in modes {
            let t = tempfile::tempdir().unwrap();
            let dir = t.path().join("s");
            Store::init_bare(&dir).unwrap();
            let victim = target.map_or(dir.clone(), |f| dir.join(f));
            fs::set_permissions(&victim, fs::Permissions::from_mode(mode)).unwrap();
            let r = Store::open(&dir);
            assert!(
                matches!(r, Err(StoreError::Writable(_))),
                "{target:?} mode {mode:o}: {:?}",
                r.err()
            );
        }
    }
}

#[test]
fn init_bare_creates_flat_private_store() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    let mut names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["index.db", "lock", "registry"]);
    for f in &names {
        assert_eq!(mode(&dir.join(f)), 0o600, "{f}");
    }
    assert!(st.registry().unwrap().is_empty());
    Store::open(&dir).expect("a freshly initialised store reopens");
}

#[test]
fn init_extant_creates_dot_ext_and_registers_dir() {
    let t = tempfile::tempdir().unwrap();
    let dir = fs::canonicalize(t.path()).unwrap();
    let st = Store::init_extant(&dir).unwrap();
    assert!(dir.join(".ext/registry").is_file());
    assert!(dir.join(".ext/index.db").is_file());
    assert!(dir.join(".ext/lock").is_file());
    let reg = st.registry().unwrap();
    assert_eq!(reg, vec![rp(dir.as_os_str().as_encoded_bytes())]);
    // `<dir>` and `<dir>/.ext` both resolve to the same store.
    let a = locate(Some(&dir), None, &dir.join("nodefault"), &dir.join("nocwd")).unwrap();
    assert_eq!(a, (dir.join(".ext"), Source::Flag));
}

#[test]
fn registry_edit_roundtrips_awkward_paths() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    let paths: Vec<Vec<u8>> = vec![
        b"/a\tb".to_vec(),
        b"/a\nb".to_vec(),
        b"/a\\b".to_vec(),
        b"/a\\x41".to_vec(),
        b"/bad\xff\xfeutf8".to_vec(),
        "/caf\u{e9}".as_bytes().to_vec(),
    ];
    let lock = st.lock().unwrap();
    st.edit_registry(&lock, |v| v.extend(paths.iter().map(|p| rp(p))))
        .unwrap();
    drop(lock);
    let mut got: Vec<Vec<u8>> = Store::open(&dir)
        .unwrap()
        .registry()
        .unwrap()
        .iter()
        .map(|r| r.as_bytes().to_vec())
        .collect();
    let mut want = paths;
    got.sort();
    want.sort();
    assert_eq!(got, want);
    // On disk it is line-oriented: embedded \n never becomes a raw line break.
    let raw = fs::read(dir.join("registry")).unwrap();
    assert_eq!(raw.iter().filter(|&&b| b == b'\n').count(), want.len());
}

/// A hand-edited registry with a bad line is rejected, naming the line.
#[test]
fn registry_read_reports_line_number() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    fs::write(dir.join("registry"), b"/ok\nrelative/path\n").unwrap();
    assert!(matches!(
        st.registry(),
        Err(StoreError::Registry { line: 2, .. })
    ));
}

/// R3: `lock()` creates a missing lock file (0600); open tolerates its absence.
#[test]
fn lock_creates_missing_lock_file() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    Store::init_bare(&dir).unwrap();
    fs::remove_file(dir.join("lock")).unwrap();
    let st = Store::open(&dir).expect("store without lock file still opens");
    let _g = st.lock().unwrap();
    let md = fs::metadata(dir.join("lock")).unwrap();
    assert!(md.is_file());
    assert_eq!(md.permissions().mode() & 0o777, 0o600);
}

/// R3/R9: the registry is replaced by rename (a new inode, no temp left
/// behind), so a reader can never see a torn file; the lock is a separate
/// file whose inode survives the rewrite.
#[test]
fn registry_rewrite_is_rename_and_lock_inode_stable() {
    use std::os::unix::fs::MetadataExt;
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    let ino = |f: &str| fs::metadata(dir.join(f)).unwrap().ino();
    let (reg_before, lock_before) = (ino("registry"), ino("lock"));
    let g = st.lock().unwrap();
    st.edit_registry(&g, |v| v.push(rp(b"/x"))).unwrap();
    assert_ne!(ino("registry"), reg_before, "registry rewritten in place");
    assert_eq!(ino("lock"), lock_before);
    let mut names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["index.db", "lock", "registry"], "stray temp file");
    assert_eq!(st.registry().unwrap(), vec![rp(b"/x")]);
}

/// R7: init never overwrites anything that exists at the target: a store
/// (bytes kept), or merely an empty directory (`.ext` for the extant form).
#[test]
fn init_never_overwrites() {
    let already = |r: Result<Store, StoreError>| {
        assert!(
            matches!(&r, Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists),
            "{:?}",
            r.err()
        );
    };
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    let g = st.lock().unwrap();
    st.edit_registry(&g, |v| v.push(rp(b"/keep"))).unwrap();
    drop(g);
    already(Store::init_bare(&dir));
    assert_eq!(
        Store::open(&dir).unwrap().registry().unwrap(),
        vec![rp(b"/keep")]
    );
    let empty = t.path().join("empty");
    fs::create_dir(&empty).unwrap();
    already(Store::init_bare(&empty));

    let base = fs::canonicalize(t.path()).unwrap();
    let with_store = base.join("x");
    fs::create_dir(&with_store).unwrap();
    Store::init_extant(&with_store).unwrap();
    already(Store::init_extant(&with_store));
    let with_empty_dot_ext = base.join("y");
    fs::create_dir_all(with_empty_dot_ext.join(".ext")).unwrap();
    already(Store::init_extant(&with_empty_dot_ext));
}
