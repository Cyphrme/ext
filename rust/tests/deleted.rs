//! Deleted roots against missing mounts (docs/traversal.md, Deleted roots).
//! A gone root is deleted only if its nearest existing ancestor is on the
//! filesystem the root was recorded on; otherwise it is a missing mount.

mod support;
use ext::digest::{Alg, Digest};
use ext::index::{Entry, Index, Meta, RootId};
use ext::scan::{run, Opts, Report, ReportKind as K, Summary};
use ext::store::Store;
use std::fs;
use std::path::PathBuf;
use support::{b, canon_tmp, rp, store_with_roots};

struct Env {
    _t: tempfile::TempDir,
    base: PathBuf,
    st: Store,
    ix: Index,
}

fn env(roots: &[&str]) -> Env {
    let (t, base) = canon_tmp();
    let dirs: Vec<PathBuf> = roots.iter().map(|r| base.join(r)).collect();
    for d in &dirs {
        fs::create_dir_all(d).unwrap();
        fs::write(d.join("f"), d.to_str().unwrap()).unwrap();
    }
    let st = store_with_roots(
        &base,
        &dirs.iter().map(PathBuf::as_path).collect::<Vec<_>>(),
    );
    let ix = Index::open(&st).unwrap();
    Env {
        _t: t,
        base,
        st,
        ix,
    }
}

fn scan(e: &Env, opts: &Opts) -> (Summary, Vec<Report>) {
    let lock = e.st.lock().unwrap();
    let mut reps = Vec::new();
    let s = run(&e.st, &lock, &e.ix, opts, &mut |r| reps.push(r)).unwrap();
    (s, reps)
}

fn kinds(reps: &[Report], k: K) -> Vec<Vec<u8>> {
    reps.iter()
        .filter(|r| r.kind == k)
        .map(|r| r.path.clone())
        .collect()
}

fn registered(e: &Env) -> Vec<Vec<u8>> {
    e.st.registry()
        .unwrap()
        .iter()
        .map(|r| r.as_bytes().to_vec())
        .collect()
}

fn indexed(e: &Env) -> Vec<Vec<u8>> {
    e.ix.iter().unwrap().into_iter().map(|x| x.path).collect()
}

#[test]
fn deleted_root_is_unregistered_and_reported() {
    let e = env(&["r"]);
    let root = e.base.join("r");
    scan(&e, &Opts::default());
    assert_eq!(indexed(&e), vec![b(&root.join("f"))]);
    fs::remove_dir_all(&root).unwrap();
    let (s, reps) = scan(&e, &Opts::default());
    assert_eq!(kinds(&reps, K::Deleted), vec![b(&root)]);
    assert_eq!(kinds(&reps, K::Missing), vec![b(&root.join("f"))]);
    assert_eq!((s.deleted, s.missing, s.refused), (1, 1, 0));
    assert_eq!(s.exit_code(), 0);
    assert!(indexed(&e).is_empty());
    assert!(registered(&e).is_empty(), "the root is unregistered");
    assert_eq!(e.ix.root_id(&rp(&root)).unwrap(), None);
}

// With the option off the deletion is only reported: the registry, the
// entries and the recorded identity stay as they were.
#[test]
fn deleted_root_with_the_option_off_changes_nothing() {
    let e = env(&["r"]);
    let root = e.base.join("r");
    scan(&e, &Opts::default());
    let id = e.ix.root_id(&rp(&root)).unwrap();
    fs::remove_dir_all(&root).unwrap();
    let off = Opts {
        unregister_deleted: false,
        ..Opts::default()
    };
    let (s, reps) = scan(&e, &off);
    assert_eq!(kinds(&reps, K::Deleted), vec![b(&root)]);
    assert!(kinds(&reps, K::Missing).is_empty(), "{reps:?}");
    assert_eq!((s.deleted, s.missing), (1, 0));
    assert_eq!(s.exit_code(), 0);
    assert_eq!(indexed(&e), vec![b(&root.join("f"))]);
    assert_eq!(registered(&e), vec![b(&root)]);
    assert_eq!(e.ix.root_id(&rp(&root)).unwrap(), id);
}

// The recorded filesystem is not the one the nearest ancestor is on: the
// root's disk is not mounted, so nothing may be forgotten.
#[test]
fn root_gone_from_another_filesystem_is_a_missing_mount() {
    let e = env(&["r"]);
    let root = e.base.join("r");
    scan(&e, &Opts::default());
    let was = e.ix.root_id(&rp(&root)).unwrap().unwrap();
    e.ix.set_root_id(&rp(&root), RootId(was.0 ^ 1)).unwrap();
    fs::remove_dir_all(&root).unwrap();
    let (s, reps) = scan(&e, &Opts::default());
    assert_eq!(kinds(&reps, K::Refused), vec![b(&root)]);
    assert!(kinds(&reps, K::Deleted).is_empty() && kinds(&reps, K::Missing).is_empty());
    assert_eq!((s.refused, s.deleted, s.missing), (1, 0, 0));
    assert_eq!(s.exit_code(), 5);
    assert_eq!(indexed(&e), vec![b(&root.join("f"))]);
    assert_eq!(registered(&e), vec![b(&root)]);
}

// A root with no recorded identity cannot be told apart from a missing
// mount, so it is treated as one.
#[test]
fn gone_root_without_a_recorded_identity_is_kept_and_refused() {
    let e = env(&["r"]);
    let root = e.base.join("r");
    let content = b"x";
    e.ix.upsert(&Entry {
        path: b(&root.join("f")),
        digest: Digest::compute(Alg::Sha256, content),
        meta: Meta {
            size: 1,
            mtime_ns: 1,
            ctime_ns: 1,
            dev: 1,
            ino: 1,
        },
        last_checked_ns: 1,
    })
    .unwrap();
    fs::remove_dir_all(&root).unwrap();
    let (s, reps) = scan(&e, &Opts::default());
    assert_eq!(kinds(&reps, K::Refused), vec![b(&root)]);
    assert_eq!((s.refused, s.deleted, s.missing), (1, 0, 0));
    assert_eq!(s.exit_code(), 5);
    assert_eq!(indexed(&e).len(), 1);
    assert_eq!(registered(&e), vec![b(&root)]);
}

// Only the deleted root goes; a registered root above it keeps its entries.
#[test]
fn deleting_a_nested_root_leaves_the_outer_root_alone() {
    let e = env(&["o", "o/i"]);
    let (outer, inner) = (e.base.join("o"), e.base.join("o/i"));
    scan(&e, &Opts::default());
    fs::remove_dir_all(&inner).unwrap();
    let (s, reps) = scan(&e, &Opts::default());
    assert_eq!(kinds(&reps, K::Deleted), vec![b(&inner)]);
    assert_eq!(s.exit_code(), 0, "{reps:?}");
    assert_eq!(registered(&e), vec![b(&outer)]);
    assert_eq!(indexed(&e), vec![b(&outer.join("f"))]);
}

#[test]
fn unmounted_root_whose_mountpoint_is_gone_is_refused_in_a_real_mount_namespace() {
    let script = r#"
mkdir -p "$J/work/root"
mount -t tmpfs tmpfs "$J/work/root" || exit 77
echo data > "$J/work/root/f"
x init --bare /work/store || exit 1
x --d /work/store register /work/root > /dev/null 2>&1 || exit 1
umount "$J/work/root" && rmdir "$J/work/root" || exit 77
x --d /work/store check
echo "CODE=$?"
x --d /work/store list
echo "LISTED=$?"
cat "$J/work/store/registry"
"#;
    let Some(o) = support::in_jail(script) else {
        eprintln!("skipped: no unprivileged user+mount namespace");
        return;
    };
    assert!(
        o.stdout.contains("REFUSED\t/work/root\t"),
        "{}{}",
        o.stdout,
        o.stderr
    );
    assert!(o.stdout.contains("CODE=5"), "{}", o.stdout);
    assert!(
        o.stdout.contains("\t/work/root/f\n"),
        "entries kept: {}",
        o.stdout
    );
    assert!(
        o.stdout.ends_with("/work/root\n"),
        "still registered: {}",
        o.stdout
    );
    assert!(!o.stdout.contains("DELETED"), "{}", o.stdout);
}

// A deleted outer root takes only its own entries: a registered root nested
// in it that is a missing mount keeps its entries and its registration.
#[test]
fn deleted_outer_root_leaves_a_nested_missing_mount_alone() {
    let script = r#"
mkdir -p "$J/work/outer/mnt"
mount -t tmpfs tmpfs "$J/work/outer/mnt" || exit 77
echo data > "$J/work/outer/mnt/f"
echo o > "$J/work/outer/g"
x init --bare /work/store || exit 1
x --d /work/store register /work/outer > /dev/null 2>&1 || exit 1
x --d /work/store register /work/outer/mnt > /dev/null 2>&1 || exit 1
umount "$J/work/outer/mnt" && rm -rf "$J/work/outer" || exit 77
x --d /work/store check
echo "CODE=$?"
echo "--list"
x --d /work/store list
echo "--registry"
cat "$J/work/store/registry"
"#;
    let Some(o) = support::in_jail(script) else {
        eprintln!("skipped: no unprivileged user+mount namespace");
        return;
    };
    let out = &o.stdout;
    assert!(out.contains("DELETED\t/work/outer\n"), "{out}{}", o.stderr);
    assert!(out.contains("REFUSED\t/work/outer/mnt\t"), "{out}");
    assert!(out.contains("CODE=5"), "{out}");
    let (_, rest) = out.split_once("--list\n").unwrap();
    let (list, registry) = rest.split_once("--registry\n").unwrap();
    assert!(list.contains("\t/work/outer/mnt/f\n"), "entry lost: {list}");
    assert!(!list.contains("/work/outer/g"), "{list}");
    assert_eq!(registry, "/work/outer/mnt\n", "{registry}");
}
