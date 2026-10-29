//! A registered root may be a single regular file (README, Commands:
//! "Supports both files and directories"): hashed, checked and, when gone,
//! judged deleted or missing like a directory root, with its parent as the
//! nearest ancestor.

mod support;
use assert_cmd::Command;
use ext::index::Index;
use ext::scan::{run, Opts, Report, ReportKind as K, Summary};
use ext::store::Store;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::Duration;
use support::{b, canon_tmp, store_with_roots};

struct Env {
    _t: tempfile::TempDir,
    file: PathBuf,
    st: Store,
    ix: Index,
}

fn env() -> Env {
    let (t, base) = canon_tmp();
    let file = base.join("one.txt");
    fs::write(&file, b"first").unwrap();
    let st = store_with_roots(&base, &[&file]);
    let ix = Index::open(&st).unwrap();
    Env {
        _t: t,
        file,
        st,
        ix,
    }
}

fn scan(e: &Env) -> (Summary, Vec<Report>) {
    let lock = e.st.lock().unwrap();
    let mut reps = Vec::new();
    let s = run(&e.st, &lock, &e.ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
    (s, reps)
}

fn kinds(reps: &[Report], k: K) -> Vec<Vec<u8>> {
    reps.iter()
        .filter(|r| r.kind == k)
        .map(|r| r.path.clone())
        .collect()
}

fn indexed(e: &Env) -> Vec<Vec<u8>> {
    e.ix.iter().unwrap().into_iter().map(|x| x.path).collect()
}

#[test]
fn a_file_root_is_hashed_and_its_edit_is_reported() {
    let e = env();
    let (s, reps) = scan(&e);
    assert_eq!(kinds(&reps, K::New), vec![b(&e.file)], "{reps:?}");
    assert_eq!(s.exit_code(), 0);
    assert_eq!(indexed(&e), vec![b(&e.file)]);
    assert!(e.ix.root_id(&support::rp(&e.file)).unwrap().is_some());
    fs::write(&e.file, b"second, longer").unwrap();
    let (_, reps) = scan(&e);
    assert_eq!(kinds(&reps, K::Edited), vec![b(&e.file)], "{reps:?}");
}

#[test]
fn a_deleted_file_root_is_unregistered_with_its_parent_as_ancestor() {
    let e = env();
    scan(&e);
    fs::remove_file(&e.file).unwrap();
    let (s, reps) = scan(&e);
    assert_eq!(kinds(&reps, K::Missing), vec![b(&e.file)], "{reps:?}");
    assert_eq!(kinds(&reps, K::Deleted), vec![b(&e.file)], "{reps:?}");
    assert_eq!(s.exit_code(), 0);
    assert!(indexed(&e).is_empty());
    assert!(e.st.registry().unwrap().is_empty());
}

// A file root whose parent is on another filesystem than the one recorded is
// a missing mount, exactly as for a directory root.
#[test]
fn a_gone_file_root_on_another_filesystem_is_refused_and_kept() {
    let e = env();
    scan(&e);
    let was = e.ix.root_id(&support::rp(&e.file)).unwrap().unwrap();
    e.ix.set_root_id(&support::rp(&e.file), ext::index::RootId(was.0 ^ 1))
        .unwrap();
    fs::remove_file(&e.file).unwrap();
    let (s, reps) = scan(&e);
    assert_eq!(kinds(&reps, K::Refused), vec![b(&e.file)], "{reps:?}");
    assert_eq!(s.exit_code(), 5);
    assert_eq!(indexed(&e), vec![b(&e.file)]);
    assert_eq!(e.st.registry().unwrap().len(), 1);
}

#[test]
fn a_symlink_as_a_file_root_is_refused_and_not_followed() {
    let (_t, base) = canon_tmp();
    let real = base.join("real");
    fs::write(&real, b"x").unwrap();
    let link = base.join("link");
    symlink(&real, &link).unwrap();
    let st = store_with_roots(&base, &[&link]);
    let ix = Index::open(&st).unwrap();
    let lock = st.lock().unwrap();
    let mut reps = Vec::new();
    let s = run(&st, &lock, &ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
    assert_eq!(kinds(&reps, K::Refused), vec![b(&link)], "{reps:?}");
    assert_eq!(s.exit_code(), 5);
    assert!(ix.iter().unwrap().is_empty());
}

// Opening a FIFO for reading blocks; a special file root must be refused
// without being opened (the test would time out otherwise).
#[test]
fn a_special_file_as_a_root_is_refused_without_opening_it() {
    let (_t, base) = canon_tmp();
    let fifo = base.join("pipe");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let st = store_with_roots(&base, &[&fifo]);
    let ix = Index::open(&st).unwrap();
    let lock = st.lock().unwrap();
    let mut reps = Vec::new();
    let s = run(&st, &lock, &ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
    assert_eq!(kinds(&reps, K::Refused), vec![b(&fifo)], "{reps:?}");
    assert_eq!(s.exit_code(), 5);
}

// A file that is also under a registered directory root is indexed once.
#[test]
fn a_file_root_inside_a_directory_root_is_indexed_once() {
    let (_t, base) = canon_tmp();
    let dir = base.join("d");
    fs::create_dir(&dir).unwrap();
    let f = dir.join("f");
    fs::write(&f, b"x").unwrap();
    fs::write(dir.join("g"), b"y").unwrap();
    let st = store_with_roots(&base, &[&dir, &f]);
    let ix = Index::open(&st).unwrap();
    let lock = st.lock().unwrap();
    let mut reps = Vec::new();
    run(&st, &lock, &ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
    assert_eq!(
        kinds(&reps, K::New).iter().filter(|p| **p == b(&f)).count(),
        1,
        "{reps:?}"
    );
    assert_eq!(ix.iter().unwrap().len(), 2);
}

// ---- through the binary: register, resolve, unregister, export, import.

fn ext(store: &Path, args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_ext"))
        .env("EXTANT_DIR", store)
        .timeout(Duration::from_secs(60))
        .args(args)
        .output()
        .unwrap();
    (
        o.status.code().unwrap(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn register_accepts_a_file_and_unregister_forgets_it() {
    let (_t, base) = canon_tmp();
    let store = base.join("store");
    Store::init_bare(&store).unwrap();
    let f = base.join("f");
    fs::write(&f, b"content").unwrap();
    let (code, out, err) = ext(&store, &["register", f.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with(&format!("NEW\t{}", f.display())), "{out}");
    let (_, list, _) = ext(&store, &["list"]);
    assert!(list.contains(&format!("\t{}\n", f.display())), "{list}");
    assert_eq!(ext(&store, &["unregister", f.to_str().unwrap()]).0, 0);
    assert!(ext(&store, &["list"]).1.is_empty());
}

#[test]
fn register_refuses_a_special_file() {
    let (_t, base) = canon_tmp();
    let store = base.join("store");
    Store::init_bare(&store).unwrap();
    let fifo = base.join("pipe");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let (code, _, err) = ext(&store, &["register", fifo.to_str().unwrap()]);
    assert_eq!(code, 4, "{err}");
}

// Imported roots have no recorded identity; the first scan records it.
#[test]
fn a_file_root_survives_export_and_import() {
    let (_t, base) = canon_tmp();
    let (s1, s2) = (base.join("s1"), base.join("s2"));
    Store::init_bare(&s1).unwrap();
    Store::init_bare(&s2).unwrap();
    let f = base.join("f");
    fs::write(&f, b"content").unwrap();
    assert_eq!(ext(&s1, &["register", f.to_str().unwrap()]).0, 0);
    let out = base.join("out");
    fs::create_dir(&out).unwrap();
    assert_eq!(ext(&s1, &["export", out.to_str().unwrap()]).0, 0);
    assert_eq!(ext(&s2, &["import", out.to_str().unwrap()]).0, 0);
    let (code, stdout, err) = ext(&s2, &["check"]);
    assert_eq!(code, 0, "{err}");
    assert!(!stdout.contains("REFUSED"), "{stdout}");
    assert!(ext(&s2, &["list"])
        .1
        .contains(&format!("\t{}\n", f.display())));
}

// ---- the store is never indexed, whatever the root is.

fn scan_roots(base: &Path, roots: &[&Path]) -> (Summary, Vec<Report>, Vec<Vec<u8>>) {
    let st = store_with_roots(base, roots);
    let ix = Index::open(&st).unwrap();
    let lock = st.lock().unwrap();
    let mut reps = Vec::new();
    let s = run(&st, &lock, &ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
    let paths = ix.iter().unwrap().into_iter().map(|e| e.path).collect();
    (s, reps, paths)
}

// A hand-edited registry bypasses `register`, so the walk refuses too.
#[test]
fn a_store_file_as_a_root_is_refused_by_the_walk() {
    for name in ["registry", "index.db", "lock"] {
        let (_t, base) = canon_tmp();
        let target = base.join("store").join(name);
        let (s, reps, paths) = scan_roots(&base, &[&target]);
        assert_eq!(
            kinds(&reps, K::Refused),
            vec![b(&target)],
            "{name}: {reps:?}"
        );
        assert_eq!(s.exit_code(), 5, "{name}");
        assert!(paths.is_empty(), "{name}: indexed {paths:?}");
    }
}

#[test]
fn the_store_directory_or_a_directory_inside_it_is_refused_as_a_root() {
    let (_t, base) = canon_tmp();
    let store = base.join("store");
    for root in [store.clone(), store.join("sub")] {
        let (_s, reps, paths) = scan_roots_in(&base, &root);
        assert_eq!(kinds(&reps, K::Refused), vec![b(&root)], "{reps:?}");
        assert!(paths.is_empty(), "indexed {paths:?}");
        fs::remove_dir_all(&store).unwrap();
    }
}

fn scan_roots_in(base: &Path, root: &Path) -> (Summary, Vec<Report>, Vec<Vec<u8>>) {
    let st = store_with_roots_unchecked(base, root);
    let ix = Index::open(&st).unwrap();
    let lock = st.lock().unwrap();
    let mut reps = Vec::new();
    let s = run(&st, &lock, &ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
    let paths = ix.iter().unwrap().into_iter().map(|e| e.path).collect();
    (s, reps, paths)
}

fn store_with_roots_unchecked(base: &Path, root: &Path) -> Store {
    let st = Store::init_bare(&base.join("store")).unwrap();
    fs::create_dir_all(root).unwrap();
    let lock = st.lock().unwrap();
    st.edit_registry(&lock, |v| *v = vec![support::rp(root)])
        .unwrap();
    drop(lock);
    st
}

// The same rule the directory walk applies to a sub-extant's store.
#[test]
fn a_file_inside_a_sub_extants_store_is_refused_as_a_root() {
    let (_t, base) = canon_tmp();
    let sub = base.join("sub");
    fs::create_dir(&sub).unwrap();
    Store::init_extant(&sub).unwrap();
    let target = sub.join(".ext/registry");
    let (s, reps, paths) = scan_roots(&base, &[&target]);
    assert_eq!(kinds(&reps, K::Refused), vec![b(&target)], "{reps:?}");
    assert_eq!(s.exit_code(), 5);
    assert!(paths.is_empty(), "{paths:?}");
}

#[test]
fn register_refuses_the_stores_own_files_and_its_sub_extants() {
    let (_t, base) = canon_tmp();
    let store = base.join("store");
    Store::init_bare(&store).unwrap();
    let sub = base.join("sub");
    fs::create_dir(&sub).unwrap();
    Store::init_extant(&sub).unwrap();
    for target in [
        store.join("registry"),
        store.join("index.db"),
        store.clone(),
        sub.join(".ext/index.db"),
        sub.join(".ext"),
    ] {
        let before = fs::read(store.join("registry")).unwrap();
        let (code, _, err) = ext(&store, &["register", target.to_str().unwrap()]);
        assert_eq!(code, 4, "{}: {err}", target.display());
        assert_eq!(fs::read(store.join("registry")).unwrap(), before);
    }
    // A control: an ordinary file beside the store is fine.
    let ok = base.join("ok");
    fs::write(&ok, b"x").unwrap();
    assert_eq!(ext(&store, &["register", ok.to_str().unwrap()]).0, 0);
    // After which a check does not report the store's own files.
    let (code, out, err) = ext(&store, &["check"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty(), "{out}");
}
