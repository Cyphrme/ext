//! Sub-extants against registration (README: a parent's scan skips a
//! sub-extant unless its directory is itself registered to the parent, in
//! which case the parent hashes its files itself and never reads its index).

mod support;
use ext::index::Index;
use ext::scan::{run, Opts, Report, ReportKind as K};
use ext::store::Store;
use std::fs;
use std::path::{Path, PathBuf};
use support::{b, canon_tmp, store_with_roots};

struct Tree {
    _t: tempfile::TempDir,
    root: PathBuf,
    sub: PathBuf,
    base: PathBuf,
}

/// `<base>/root/{top, s/{inner}}` where `s` holds a real store of its own.
fn tree() -> Tree {
    let (t, base) = canon_tmp();
    let (root, sub) = (base.join("root"), base.join("root/s"));
    fs::create_dir_all(&sub).unwrap();
    fs::write(root.join("top"), b"top").unwrap();
    fs::write(sub.join("inner"), b"inner").unwrap();
    Store::init_extant(&sub).unwrap();
    Tree {
        _t: t,
        root,
        sub,
        base,
    }
}

fn scan(t: &Tree, roots: &[&Path]) -> (Vec<Report>, Vec<Vec<u8>>) {
    let st = store_with_roots(&t.base, roots);
    let ix = Index::open(&st).unwrap();
    let lock = st.lock().unwrap();
    let mut reps = Vec::new();
    run(&st, &lock, &ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
    let paths = ix.iter().unwrap().into_iter().map(|e| e.path).collect();
    (reps, paths)
}

fn has(paths: &[Vec<u8>], p: &Path) -> bool {
    paths.contains(&b(p))
}

fn nothing_from_a_store(paths: &[Vec<u8>], sub: &Path) {
    let ext = b(&sub.join(".ext"));
    assert!(
        !paths.iter().any(|p| p.starts_with(&ext)),
        "the sub-extant's own store was indexed: {paths:?}"
    );
}

#[test]
fn unregistered_sub_extant_is_skipped() {
    let t = tree();
    let (reps, paths) = scan(&t, &[&t.root]);
    assert!(reps
        .iter()
        .any(|r| r.kind == K::SubExtant && r.path == b(&t.sub)));
    assert!(has(&paths, &t.root.join("top")));
    assert!(!has(&paths, &t.sub.join("inner")));
    nothing_from_a_store(&paths, &t.sub);
}

#[test]
fn registered_sub_extant_is_hashed_by_the_parent() {
    // A fresh tree each time: `scan` creates the store.
    for n in [2, 1] {
        let t = tree();
        let all = [t.root.as_path(), t.sub.as_path()];
        let (reps, paths) = scan(&t, &all[2 - n..]);
        assert!(
            reps.iter().all(|r| r.kind != K::SubExtant),
            "{n} roots: {reps:?}"
        );
        assert!(
            reps.iter()
                .any(|r| r.kind == K::New && r.path == b(&t.sub.join("inner"))),
            "{n} roots: {reps:?}"
        );
        assert!(has(&paths, &t.sub.join("inner")), "{n} roots");
        nothing_from_a_store(&paths, &t.sub);
    }
}

// The outer walk stops at the inner root, so the file is indexed once and
// the sub-extant is not reported as excluded from the outer scan either.
#[test]
fn registered_sub_extant_under_a_registered_root_is_indexed_once() {
    let t = tree();
    let (reps, _) = scan(&t, &[&t.root, &t.sub]);
    let news = reps
        .iter()
        .filter(|r| r.kind == K::New && r.path == b(&t.sub.join("inner")))
        .count();
    assert_eq!(news, 1, "{reps:?}");
    assert!(reps.iter().all(|r| r.kind != K::Excluded), "{reps:?}");
}

// README, Subdirectory Registration: the marker is a `.ext/` directory
// holding a registry. A sub-extant made by another implementation has no
// index.db or lock of ours, and must still not be indexed as content.
#[test]
fn a_dot_ext_with_only_a_registry_is_a_sub_extant() {
    let t = tree();
    let ext = t.sub.join(".ext");
    for f in ["index.db", "lock"] {
        fs::remove_file(ext.join(f)).unwrap();
    }
    let (reps, paths) = scan(&t, &[&t.root]);
    assert!(
        reps.iter()
            .any(|r| r.kind == K::SubExtant && r.path == b(&t.sub)),
        "{reps:?}"
    );
    assert!(!has(&paths, &t.sub.join("inner")));
    nothing_from_a_store(&paths, &t.sub);
}

// Hardening beyond the spec: a group-writable `.ext` is not trusted to hide
// a subtree, whatever it holds.
#[test]
fn a_group_writable_dot_ext_does_not_exclude() {
    use std::os::unix::fs::PermissionsExt;
    let t = tree();
    fs::set_permissions(t.sub.join(".ext"), fs::Permissions::from_mode(0o770)).unwrap();
    let (reps, paths) = scan(&t, &[&t.root]);
    assert!(reps.iter().all(|r| r.kind != K::SubExtant), "{reps:?}");
    assert!(has(&paths, &t.sub.join("inner")));
}
