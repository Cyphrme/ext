//! Plan §1 "Skip and racy rule", "check" table, §4 `scan.rs` (A1, A2, A4,
//! A8, R8, R9, T1, T4). Real trees; the clock-independent skip/racy logic is
//! pinned purely in tests/fresh.rs, so here "not racy" is arranged by moving
//! the stored `last_checked_ns` forward rather than by sleeping.

mod support;
use ext::digest::{Alg, Digest};
use ext::index::{Entry, Index};
use ext::scan::{run, run_hooked, Opts, Report, ReportKind as K, Summary};
use ext::store::{Store, StoreError};
use rustix::fs::{mknodat, FileType, Mode, CWD};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;
use support::{b, canon_tmp, rp, store_with_roots, time_from_ns};

const HOUR_NS: i64 = 3_600_000_000_000;

struct Env {
    _t: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    st: Store,
    ix: Index,
}

fn env() -> Env {
    let (t, base) = canon_tmp();
    let root = base.join("root");
    fs::create_dir_all(&root).unwrap();
    let st = store_with_roots(&base, &[&root]);
    let ix = Index::open(&st).unwrap();
    Env {
        _t: t,
        base,
        root,
        st,
        ix,
    }
}

fn scan(e: &Env, opts: &Opts) -> (Summary, Vec<Report>) {
    let mut reps = Vec::new();
    let lock = e.st.lock().unwrap();
    let s = run(&e.st, &lock, &e.ix, opts, &mut |r| reps.push(r)).unwrap();
    (s, reps)
}

fn kinds(reps: &[Report], k: K) -> Vec<Vec<u8>> {
    reps.iter()
        .filter(|r| r.kind == k)
        .map(|r| r.path.clone())
        .collect()
}

fn entry(e: &Env, p: &Path) -> Option<Entry> {
    e.ix.get(&b(p)).unwrap()
}

/// Make every stored entry non-racy by pretending it was checked an hour
/// later, leaving the file metadata untouched.
fn settle(e: &Env) {
    for mut en in e.ix.iter().unwrap() {
        en.last_checked_ns += HOUR_NS;
        e.ix.upsert(&en).unwrap();
    }
}

fn tamper(e: &Env, p: &Path) -> Entry {
    let mut en = entry(e, p).expect("indexed");
    en.digest = Digest::compute(Alg::Sha256, b"tampered");
    e.ix.upsert(&en).unwrap();
    en
}

fn tampered_digest() -> Digest {
    Digest::compute(Alg::Sha256, b"tampered")
}

fn digest_of(p: &Path) -> Digest {
    Digest::compute(Alg::Sha256, &fs::read(p).unwrap())
}

#[test]
fn first_scan_reports_new_and_indexes_every_file() {
    let e = env();
    fs::create_dir_all(e.root.join("d")).unwrap();
    fs::write(e.root.join("a"), b"alpha").unwrap();
    fs::write(e.root.join("d/b"), b"beta").unwrap();
    let (s, reps) = scan(&e, &Opts::default());
    assert_eq!(s.new, 2);
    assert_eq!(s.exit_code(), 0);
    let mut new = kinds(&reps, K::New);
    new.sort();
    assert_eq!(new, vec![b(&e.root.join("a")), b(&e.root.join("d/b"))]);
    for f in ["a", "d/b"] {
        let p = e.root.join(f);
        assert_eq!(entry(&e, &p).unwrap().digest, digest_of(&p));
    }
}

#[test]
fn settled_unchanged_entry_is_skipped_not_rehashed() {
    let e = env();
    let f = e.root.join("f");
    fs::write(&f, b"content").unwrap();
    scan(&e, &Opts::default());
    settle(&e);
    let t = tamper(&e, &f);
    let (s, reps) = scan(&e, &Opts::default());
    assert_eq!((s.skipped, s.new, s.edited, s.violation), (1, 0, 0, 0));
    assert!(reps.is_empty(), "{reps:?}");
    // The tampered digest survives only if the file was never re-read.
    assert_eq!(entry(&e, &f).unwrap().digest, t.digest);
}

// A2/T2: a racy entry is re-hashed even though every metadata field matches.
#[test]
fn racy_entry_is_rehashed_and_corrected() {
    let e = env();
    let f = e.root.join("f");
    fs::write(&f, b"content").unwrap();
    scan(&e, &Opts::default());
    let mut en = tamper(&e, &f);
    en.last_checked_ns = en.meta.mtime_ns.max(en.meta.ctime_ns);
    e.ix.upsert(&en).unwrap();
    let (s, reps) = scan(&e, &Opts::default());
    assert_eq!((s.skipped, s.edited), (0, 1));
    assert_eq!(kinds(&reps, K::Edited), vec![b(&f)]);
    assert_eq!(reps[0].digests, Some((tampered_digest(), digest_of(&f))));
    assert_eq!(entry(&e, &f).unwrap().digest, digest_of(&f));
}

// Unchanged after re-hash: nothing printed, but last_checked is refreshed.
#[test]
fn unchanged_rehash_is_silent_and_refreshes_last_checked() {
    let e = env();
    let f = e.root.join("f");
    fs::write(&f, b"content").unwrap();
    scan(&e, &Opts::default());
    let before = entry(&e, &f).unwrap();
    sleep(Duration::from_millis(5));
    let (s, reps) = scan(&e, &Opts::default()); // racy: just written
    assert_eq!((s.unchanged, s.new, s.edited), (1, 0, 0));
    assert!(reps.is_empty(), "{reps:?}");
    assert!(entry(&e, &f).unwrap().last_checked_ns > before.last_checked_ns);
}

// T1: same size, mtime restored, entry settled (so racy cannot explain the
// catch). Only the changed ctime can reveal the edit.
#[test]
fn same_size_edit_with_mtime_restored_is_caught_by_ctime() {
    let e = env();
    let f = e.root.join("f");
    fs::write(&f, b"AAAAAAAA").unwrap();
    scan(&e, &Opts::default());
    settle(&e);
    let stored = entry(&e, &f).unwrap();
    sleep(Duration::from_millis(50)); // leave the creation tick of the coarse clock
    fs::write(&f, b"BBBBBBBB").unwrap();
    OpenOptions::new()
        .write(true)
        .open(&f)
        .unwrap()
        .set_modified(time_from_ns(stored.meta.mtime_ns))
        .unwrap();
    use std::os::unix::fs::MetadataExt;
    let md = fs::metadata(&f).unwrap();
    assert_eq!(md.len(), stored.meta.size, "test premise: same size");
    assert_eq!(
        md.mtime() * 1_000_000_000 + md.mtime_nsec(),
        stored.meta.mtime_ns,
        "test premise: mtime restored"
    );
    assert_ne!(
        md.ctime() * 1_000_000_000 + md.ctime_nsec(),
        stored.meta.ctime_ns,
        "test premise: ctime moved"
    );
    let (s, reps) = scan(&e, &Opts::default());
    assert_eq!(s.edited, 1);
    assert_eq!(kinds(&reps, K::Edited), vec![b(&f)]);
    assert_eq!(
        reps[0].digests,
        Some((stored.digest.clone(), digest_of(&f)))
    );
    assert_eq!(entry(&e, &f).unwrap().digest, digest_of(&f));
}

// D1/C5: a violation under --full is reported, exits 2 and is not written;
// --accept writes it, counts it as accepted and exits 0.
#[test]
fn violation_then_accept() {
    let e = env();
    let f = e.root.join("f");
    fs::write(&f, b"content").unwrap();
    scan(&e, &Opts::default());
    settle(&e);
    let t = tamper(&e, &f);
    let full = Opts {
        full: true,
        ..Opts::default()
    };
    let (s, reps) = scan(&e, &full);
    assert_eq!((s.violation, s.accepted), (1, 0));
    assert_eq!(s.exit_code(), 2);
    assert_eq!(kinds(&reps, K::Violation), vec![b(&f)]);
    assert_eq!(reps[0].digests, Some((t.digest.clone(), digest_of(&f))));
    assert_eq!(
        entry(&e, &f).unwrap().digest,
        t.digest,
        "index must not change"
    );

    let (s, reps) = scan(
        &e,
        &Opts {
            accept: true,
            ..full
        },
    );
    assert_eq!((s.violation, s.accepted), (0, 1));
    assert_eq!(kinds(&reps, K::Accepted), vec![b(&f)]);
    assert_eq!(entry(&e, &f).unwrap().digest, digest_of(&f));
    assert_eq!(s.exit_code(), 0, "an accepted violation is not an error");
}

#[test]
fn deleted_file_is_missing_and_its_entry_removed() {
    let e = env();
    let f = e.root.join("f");
    fs::write(&f, b"content").unwrap();
    fs::write(e.root.join("keep"), b"k").unwrap();
    scan(&e, &Opts::default());
    fs::remove_file(&f).unwrap();
    let (s, reps) = scan(&e, &Opts::default());
    assert_eq!(s.missing, 1);
    assert_eq!(s.exit_code(), 0);
    assert_eq!(kinds(&reps, K::Missing), vec![b(&f)]);
    assert!(entry(&e, &f).is_none());
    assert!(entry(&e, &e.root.join("keep")).is_some());
}

// A1: content under a directory that gains `.ext/` is EXCLUDED, not MISSING.
#[test]
fn indexed_file_under_new_subextant_is_excluded_and_removed() {
    let e = env();
    fs::create_dir_all(e.root.join("d")).unwrap();
    let f = e.root.join("d/f");
    fs::write(&f, b"content").unwrap();
    scan(&e, &Opts::default());
    assert!(entry(&e, &f).is_some());
    // 26f: only a real store makes `d` a sub-extant.
    Store::init_extant(&e.root.join("d")).unwrap();
    let (s, reps) = scan(&e, &Opts::default());
    assert_eq!((s.excluded, s.missing, s.subextant), (1, 0, 1));
    assert_eq!(kinds(&reps, K::Excluded), vec![b(&f)]);
    assert_eq!(kinds(&reps, K::SubExtant), vec![b(&e.root.join("d"))]);
    assert!(entry(&e, &f).is_none());
    assert_eq!(
        s.exit_code(),
        0,
        "a skipped sub-extant is not an incomplete scan"
    );
}

#[test]
fn symlinks_and_specials_are_counted_and_not_indexed() {
    let e = env();
    let out = e.base.join("outside");
    fs::write(&out, b"secret").unwrap();
    symlink(&out, e.root.join("link")).unwrap();
    mknodat(
        CWD,
        e.root.join("fifo"),
        FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    fs::write(e.root.join("f"), b"x").unwrap();
    let (s, _) = scan(&e, &Opts::default());
    assert_eq!((s.symlinks, s.special, s.new), (1, 1, 1));
    assert!(entry(&e, &e.root.join("fifo")).is_none());
    assert!(entry(&e, &e.root.join("link")).is_none());
    assert!(entry(&e, &out).is_none());
}

#[test]
fn refused_root_is_reported_exit_5_and_other_roots_still_scan() {
    let (t, base) = canon_tmp();
    let _keep = t;
    fs::create_dir_all(base.join("real/bad")).unwrap();
    symlink(base.join("real"), base.join("link")).unwrap();
    let good = base.join("good");
    fs::create_dir_all(&good).unwrap();
    fs::write(good.join("f"), b"x").unwrap();
    let bad = base.join("link/bad");
    let st = store_with_roots(&base, &[&bad, &good]);
    let ix = Index::open(&st).unwrap();
    let mut reps = Vec::new();
    let lock = st.lock().unwrap();
    let s = run(&st, &lock, &ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
    assert_eq!(s.refused, 1);
    assert_eq!(s.exit_code(), 5);
    assert_eq!(kinds(&reps, K::Refused), vec![b(&bad)]);
    assert!(ix.get(&b(&good.join("f"))).unwrap().is_some());
}

// Per-file failures are reports, not aborts: a new unreadable file is not
// indexed, siblings still are, and an unreadable file's existing entry stays
// (its content is not known to have changed; contrast Unstable, which drops).
#[test]
fn unreadable_file() {
    if support::is_root() {
        eprintln!("skipped: root ignores mode 000");
        return;
    }
    let e = env();
    let old = e.root.join("old");
    fs::write(&old, b"x").unwrap();
    scan(&e, &Opts::default());
    let before = entry(&e, &old).unwrap();
    settle(&e);
    // chmod changes ctime, so the entry is not skippable and the file is opened.
    sleep(Duration::from_millis(50));
    fs::set_permissions(&old, fs::Permissions::from_mode(0o000)).unwrap();
    let new = e.root.join("locked");
    fs::write(&new, b"x").unwrap();
    fs::set_permissions(&new, fs::Permissions::from_mode(0o000)).unwrap();
    fs::write(e.root.join("ok"), b"y").unwrap();
    let (s, reps) = scan(&e, &Opts::default());
    for p in [&old, &new] {
        fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!((s.error, s.new, s.missing), (2, 1, 0));
    assert_eq!(s.exit_code(), 5);
    let mut errs = kinds(&reps, K::Error);
    errs.sort();
    assert_eq!(errs, vec![b(&new), b(&old)]);
    assert!(entry(&e, &new).is_none());
    assert!(entry(&e, &e.root.join("ok")).is_some());
    assert_eq!(entry(&e, &old).unwrap().digest, before.digest);
}

fn big_file(p: &Path, fill: u8) {
    fs::write(p, vec![fill; 1 << 20]).unwrap();
}

// A8/T4: unstable on the first attempt and again on the one retry => the
// stale entry is deleted, never left to be served.
#[test]
fn persistently_unstable_file_is_reported_and_entry_dropped() {
    let e = env();
    let f = e.root.join("f");
    big_file(&f, b'a');
    scan(&e, &Opts::default());
    assert!(entry(&e, &f).is_some());
    big_file(&f, b'b'); // stale entry now disagrees with the file
    let mut mutations = 0;
    let mut reps = Vec::new();
    let lock = e.st.lock().unwrap();
    let s = run_hooked(
        &e.st,
        &lock,
        &e.ix,
        &Opts::default(),
        &mut |path, _| {
            assert_eq!(path, b(&f).as_slice());
            if mutations < 50 {
                mutations += 1;
                OpenOptions::new()
                    .append(true)
                    .open(&f)
                    .unwrap()
                    .write_all(b"x")
                    .unwrap();
            }
        },
        &mut |r| reps.push(r),
    )
    .unwrap();
    assert_eq!(s.unstable, 1);
    assert_eq!(s.exit_code(), 5);
    assert_eq!(kinds(&reps, K::Unstable), vec![b(&f)]);
    assert!(entry(&e, &f).is_none(), "stale entry must not survive");
    assert!(e.ix.by_digest(&digest_of(&f)).unwrap().is_empty());
}

// The retry is real: one mid-hash change followed by a quiet second attempt
// succeeds and records the final content.
#[test]
fn single_mid_hash_change_is_absorbed_by_one_retry() {
    let e = env();
    let f = e.root.join("f");
    big_file(&f, b'a');
    let mut done = false;
    let mut reps = Vec::new();
    let lock = e.st.lock().unwrap();
    let s = run_hooked(
        &e.st,
        &lock,
        &e.ix,
        &Opts::default(),
        &mut |_, _| {
            if !done {
                done = true;
                OpenOptions::new()
                    .append(true)
                    .open(&f)
                    .unwrap()
                    .write_all(b"x")
                    .unwrap();
            }
        },
        &mut |r| reps.push(r),
    )
    .unwrap();
    assert!(done, "hook never fired; test would prove nothing");
    assert_eq!((s.unstable, s.new), (0, 1));
    assert_eq!(s.exit_code(), 0);
    assert_eq!(entry(&e, &f).unwrap().digest, digest_of(&f));
}

// R8: `run` reconciles before walking, so a stale index plus a registry edit
// converges in one run, with no separate command.
#[test]
fn run_reconciles_index_to_registry() {
    let (t, base) = canon_tmp();
    let _keep = t;
    let (a, bdir) = (base.join("a"), base.join("b"));
    for d in [&a, &bdir] {
        fs::create_dir_all(d).unwrap();
        fs::write(d.join("f"), b"x").unwrap();
    }
    let st = store_with_roots(&base, &[&a, &bdir]);
    let ix = Index::open(&st).unwrap();
    let lock = st.lock().unwrap();
    run(&st, &lock, &ix, &Opts::default(), &mut |_| {}).unwrap();
    drop(lock);
    assert_eq!(ix.iter().unwrap().len(), 2);

    // Unregister `a` by hand-editing the registry, and plant an entry that
    // belongs to no root at all.
    let lock = st.lock().unwrap();
    st.edit_registry(&lock, |v| *v = vec![rp(&bdir)]).unwrap();
    drop(lock);
    let mut stray = ix.get(&b(&bdir.join("f"))).unwrap().unwrap();
    stray.path = b"/nowhere/at/all".to_vec();
    ix.upsert(&stray).unwrap();

    let lock = st.lock().unwrap();
    let s = run(&st, &lock, &ix, &Opts::default(), &mut |_| {}).unwrap();
    assert_eq!(s.exit_code(), 0);
    let paths: Vec<_> = ix.iter().unwrap().into_iter().map(|x| x.path).collect();
    assert_eq!(paths, vec![b(&bdir.join("f"))]);
}

#[test]
fn exit_code_precedence() {
    let z = Summary::default();
    assert_eq!(z.exit_code(), 0);
    let informational = Summary {
        new: 3,
        edited: 2,
        missing: 1,
        excluded: 1,
        symlinks: 9,
        special: 9,
        subextant: 1,
        mount: 1,
        accepted: 4,
        ..z
    };
    assert_eq!(
        informational.exit_code(),
        0,
        "informational counts do not fail the run"
    );
    for s in [
        Summary { error: 1, ..z },
        Summary { unstable: 1, ..z },
        Summary { refused: 1, ..z },
    ] {
        assert_eq!(s.exit_code(), 5, "{s:?}");
    }
    assert_eq!(Summary { violation: 1, ..z }.exit_code(), 2);
    assert_eq!(
        Summary {
            violation: 1,
            unstable: 1,
            error: 1,
            ..z
        }
        .exit_code(),
        2
    );
}

fn paths(e: &Env) -> Vec<Vec<u8>> {
    e.ix.iter().unwrap().into_iter().map(|x| x.path).collect()
}

// C8(i): README L233, a deleted registered root is a deletion.
#[test]
fn deleted_registered_root_reports_each_entry_missing_and_exits_0() {
    let e = env();
    fs::create_dir_all(e.root.join("d")).unwrap();
    fs::write(e.root.join("a"), b"1").unwrap();
    fs::write(e.root.join("d/b"), b"2").unwrap();
    scan(&e, &Opts::default());
    assert_eq!(paths(&e).len(), 2);
    fs::remove_dir_all(&e.root).unwrap();
    let (s, reps) = scan(&e, &Opts::default());
    assert_eq!((s.missing, s.refused, s.error), (2, 0, 0));
    assert_eq!(s.exit_code(), 0);
    let mut m = kinds(&reps, K::Missing);
    m.sort();
    assert_eq!(m, vec![b(&e.root.join("a")), b(&e.root.join("d/b"))]);
    assert!(paths(&e).is_empty());
}

// C8(ii): a root refused for any reason other than ENOENT says nothing about
// its files, so their entries survive.
#[test]
fn refused_root_keeps_its_entries_and_reports_no_missing() {
    let (t, base) = canon_tmp();
    let _keep = t;
    fs::create_dir_all(base.join("real/root")).unwrap();
    fs::write(base.join("real/root/f"), b"x").unwrap();
    let via = base.join("link/root");
    let st = store_with_roots(&base, &[&base.join("real/root")]);
    let ix = Index::open(&st).unwrap();
    {
        let lock = st.lock().unwrap();
        run(&st, &lock, &ix, &Opts::default(), &mut |_| {}).unwrap();
    }
    let before = ix.iter().unwrap();
    assert_eq!(before.len(), 1);
    // Re-register the same tree through a symlinked parent; entries from the
    // earlier scan sit under the refused path only if their paths match, so
    // rewrite them to live under `via`.
    symlink(base.join("real"), base.join("link")).unwrap();
    for mut en in before {
        ix.remove(&en.path).unwrap();
        en.path = b(&via.join("f"));
        ix.upsert(&en).unwrap();
    }
    {
        let lock = st.lock().unwrap();
        st.edit_registry(&lock, |v| *v = vec![rp(&via)]).unwrap();
    }
    let mut reps = Vec::new();
    let lock = st.lock().unwrap();
    let s = run(&st, &lock, &ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
    assert_eq!((s.refused, s.missing), (1, 0));
    assert_eq!(s.exit_code(), 5);
    assert!(kinds(&reps, K::Missing).is_empty());
    assert!(ix.get(&b(&via.join("f"))).unwrap().is_some(), "entry lost");
}

// C8(iii): an unreadable directory must not wipe its own index entries.
#[test]
fn unreadable_subdirectory_keeps_entries_and_reports_error_not_missing() {
    if support::is_root() {
        eprintln!("skipped: root ignores mode 000");
        return;
    }
    let e = env();
    fs::create_dir_all(e.root.join("d")).unwrap();
    fs::write(e.root.join("d/f"), b"x").unwrap();
    fs::write(e.root.join("ok"), b"y").unwrap();
    scan(&e, &Opts::default());
    assert_eq!(paths(&e).len(), 2);
    let d = e.root.join("d");
    fs::set_permissions(&d, fs::Permissions::from_mode(0o000)).unwrap();
    let (s, reps) = scan(&e, &Opts::default());
    // Restore so the temp dir can be cleaned up even if an assert fails.
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!((s.error, s.missing), (1, 0));
    assert_eq!(s.exit_code(), 5);
    assert_eq!(kinds(&reps, K::Error), vec![b(&d)]);
    assert!(kinds(&reps, K::Missing).is_empty());
    assert_eq!(
        paths(&e).len(),
        2,
        "entries under the unreadable dir must survive"
    );
}

// C10/C8: `only` narrows the walk and the Missing check but not reconcile,
// and must name a registered root exactly.
#[test]
fn only_narrows_scan_not_reconcile() {
    let (t, base) = canon_tmp();
    let _keep = t;
    let (a, bd) = (base.join("a"), base.join("b"));
    for d in [&a, &bd] {
        fs::create_dir_all(d).unwrap();
        fs::write(d.join("old"), b"o").unwrap();
    }
    let st = store_with_roots(&base, &[&a, &bd]);
    let ix = Index::open(&st).unwrap();
    let lock = st.lock().unwrap();
    run(&st, &lock, &ix, &Opts::default(), &mut |_| {}).unwrap();
    fs::write(a.join("new_a"), b"n").unwrap();
    fs::write(bd.join("new_b"), b"n").unwrap();
    fs::remove_file(bd.join("old")).unwrap();
    let only_a = Opts {
        only: Some(rp(&a)),
        ..Opts::default()
    };
    let mut reps = Vec::new();
    let s = run(&st, &lock, &ix, &only_a, &mut |r| reps.push(r)).unwrap();
    assert_eq!(s.new, 1);
    assert_eq!(kinds(&reps, K::New), vec![b(&a.join("new_a"))]);
    assert!(kinds(&reps, K::Missing).is_empty(), "b is out of scope");
    assert!(ix.get(&b(&bd.join("new_b"))).unwrap().is_none());
    assert!(
        ix.get(&b(&bd.join("old"))).unwrap().is_some(),
        "b untouched"
    );

    // Not a registered root: a subdirectory of one, or a stranger.
    fs::create_dir_all(a.join("sub")).unwrap();
    for bad in [a.join("sub"), base.join("elsewhere")] {
        let opts = Opts {
            only: Some(rp(&bad)),
            ..Opts::default()
        };
        let r = run(&st, &lock, &ix, &opts, &mut |_| {});
        assert!(
            matches!(r, Err(StoreError::NotRegistered(_))),
            "{bad:?}: {r:?}"
        );
    }

    // Reconcile still covers every root: unregister b, scan only a.
    st.edit_registry(&lock, |v| v.retain(|r| r != &rp(&bd)))
        .unwrap();
    run(&st, &lock, &ix, &only_a, &mut |_| {}).unwrap();
    let left: Vec<_> = ix.iter().unwrap().into_iter().map(|x| x.path).collect();
    assert_eq!(left, vec![b(&a.join("new_a")), b(&a.join("old"))]);
}

// ---------------------------------------------------------------------------
// Amendment 26f: red tests for the scanner rework.

fn assert_detail(reps: &[Report], kind: K) {
    let r = reps
        .iter()
        .find(|r| r.kind == kind)
        .unwrap_or_else(|| panic!("no {kind:?} report in {reps:?}"));
    assert!(
        r.detail.as_deref().is_some_and(|d| !d.is_empty()),
        "{kind:?} report has no detail: {r:?}"
    );
}

#[test]
fn error_report_carries_the_detail() {
    if support::is_root() {
        eprintln!("skipped: root ignores mode 000");
        return;
    }
    let e = env();
    let bad = e.root.join("locked");
    fs::write(&bad, b"x").unwrap();
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o000)).unwrap();
    let (_, reps) = scan(&e, &Opts::default());
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o600)).unwrap();
    assert_detail(&reps, K::Error);
}

#[test]
fn refused_report_carries_the_detail() {
    let (t, base) = canon_tmp();
    let _keep = t;
    fs::create_dir_all(base.join("real/bad")).unwrap();
    symlink(base.join("real"), base.join("link")).unwrap();
    let st = store_with_roots(&base, &[&base.join("link/bad")]);
    let ix = Index::open(&st).unwrap();
    let lock = st.lock().unwrap();
    let mut reps = Vec::new();
    run(&st, &lock, &ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
    assert_detail(&reps, K::Refused);
}

#[test]
fn unstable_report_carries_the_detail() {
    let e = env();
    let f = e.root.join("f");
    big_file(&f, b'a');
    let mut reps = Vec::new();
    let lock = e.st.lock().unwrap();
    run_hooked(
        &e.st,
        &lock,
        &e.ix,
        &Opts::default(),
        &mut |_, _| {
            OpenOptions::new()
                .append(true)
                .open(&f)
                .unwrap()
                .write_all(b"x")
                .unwrap();
        },
        &mut |r| reps.push(r),
    )
    .unwrap();
    assert_detail(&reps, K::Unstable);
}

// A directory named `.ext` makes its parent a sub-extant only if it is a
// real store: registry, index.db and lock present, not group/other-writable.
// Anything else is an ordinary directory, walked and indexed normally.
#[test]
fn only_a_real_store_dot_ext_excludes() {
    let e = env();
    for d in ["empty", "loose", "real"] {
        fs::create_dir_all(e.root.join(d)).unwrap();
        fs::write(e.root.join(d).join("f"), d.as_bytes()).unwrap();
    }
    fs::create_dir(e.root.join("empty/.ext")).unwrap();
    let loose = e.root.join("loose/.ext");
    fs::create_dir(&loose).unwrap();
    for f in ["registry", "index.db", "lock"] {
        fs::write(loose.join(f), b"").unwrap();
    }
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o770)).unwrap();
    Store::init_extant(&e.root.join("real")).unwrap();

    let (s, reps) = scan(&e, &Opts::default());
    let mut new = kinds(&reps, K::New);
    new.sort();
    let mut want: Vec<_> = [
        "empty/f",
        "loose/f",
        "loose/.ext/registry",
        "loose/.ext/index.db",
        "loose/.ext/lock",
    ]
    .iter()
    .map(|p| b(&e.root.join(p)))
    .collect();
    want.sort();
    assert_eq!(new, want);
    assert_eq!(kinds(&reps, K::SubExtant), vec![b(&e.root.join("real"))]);
    assert_eq!(s.subextant, 1);
}

// F2: a path that comes back during the walk, after its directory was
// already listed, is not Missing and keeps its entry. A MISSING candidate is
// re-checked against the filesystem before its entry is deleted.
#[test]
fn file_arriving_in_an_already_walked_directory_is_not_missing() {
    let e = env();
    let stash = e.base.join("stash");
    fs::create_dir(&stash).unwrap();
    for d in ["d1", "d2"] {
        fs::create_dir_all(e.root.join(d)).unwrap();
        fs::write(e.root.join(d).join("g"), d.as_bytes()).unwrap();
    }
    scan(&e, &Opts::default());
    // Out of the tree for the next scan; fresh files make it hash something.
    for d in ["d1", "d2"] {
        fs::rename(e.root.join(d).join("g"), stash.join(d)).unwrap();
        fs::write(e.root.join(d).join("h"), format!("fresh {d}")).unwrap();
    }
    let mut first_dir: Option<PathBuf> = None;
    let mut restored: Option<PathBuf> = None;
    let mut reps = Vec::new();
    let lock = e.st.lock().unwrap();
    run_hooked(
        &e.st,
        &lock,
        &e.ix,
        &Opts::default(),
        &mut |path, _| {
            let dir = Path::new(std::str::from_utf8(path).unwrap())
                .parent()
                .unwrap()
                .to_path_buf();
            match &first_dir {
                None => first_dir = Some(dir),
                // First file of the second directory: the first directory is
                // completely walked, and its `g` comes back now.
                Some(first) if *first != dir && restored.is_none() => {
                    let name = first.file_name().unwrap();
                    fs::rename(stash.join(name), first.join("g")).unwrap();
                    restored = Some(first.join("g"));
                }
                Some(_) => {}
            }
        },
        &mut |r| reps.push(r),
    )
    .unwrap();
    let back = restored.expect("hook never restored the file");
    let gone = if back.starts_with(e.root.join("d1")) {
        "d2"
    } else {
        "d1"
    };
    assert_eq!(
        kinds(&reps, K::Missing),
        vec![b(&e.root.join(gone).join("g"))]
    );
    assert!(
        entry(&e, &back).is_some(),
        "entry of the returned file was deleted"
    );
}

// A root's filesystem identity is recorded when it is first scanned. If a
// later run finds a different one (an unmounted or newly mounted filesystem),
// the root is REFUSED, its entries are kept, and the run exits 5 rather than
// reporting every file Missing.
#[test]
fn root_device_change_is_refused_and_keeps_entries() {
    let script = r#"
mkdir -p "$J/work/root"
echo data > "$J/work/root/f"
x init --bare /work/store || exit 1
x --d /work/store register /work/root > /dev/null 2>&1 || exit 1
mount -t tmpfs tmpfs "$J/work/root" || exit 77
x --d /work/store check
echo "CODE=$?"
echo "--list"
x --d /work/store list
"#;
    let Some(o) = support::in_jail(script) else {
        eprintln!("skipped: no unprivileged user+mount namespace");
        return;
    };
    assert_eq!(o.code, 0, "{}", o.stderr);
    let (check, list) = o.stdout.split_once("--list\n").unwrap();
    assert!(check.contains("CODE=5"), "{check}{}", o.stderr);
    assert!(check.contains("REFUSED\t/work/root"), "{check}");
    assert!(!check.contains("MISSING"), "{check}");
    assert!(
        list.contains("\t/work/root/f\n"),
        "entry was dropped: {list}"
    );
}

// The walk is iterative and holds no descriptor per level: a chain far deeper
// than the stack or the descriptor limit allows for recursion is walked.
#[test]
fn very_deep_tree_is_walked_without_crashing() {
    use rustix::fs::{mkdirat, openat, unlinkat, AtFlags, Mode, OFlags, CWD};
    use rustix::process::{getrlimit, setrlimit, Resource};
    const DEPTH: usize = 20_000;
    // Descriptors are not what is being tested; keep them from limiting the
    // recursion that the stack is supposed to limit.
    let mut lim = getrlimit(Resource::Nofile);
    lim.current = lim.maximum;
    setrlimit(Resource::Nofile, lim).unwrap();
    if lim.maximum.is_some_and(|m| m < DEPTH as u64 + 100) {
        eprintln!(
            "skipped: hard RLIMIT_NOFILE {:?} too low to build the chain",
            lim.maximum
        );
        return;
    }
    let e = env();
    let dir = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    // mkdirat/openat by fd: the path would exceed PATH_MAX long before this.
    let mut fds = vec![openat(CWD, &e.root, dir, Mode::empty()).unwrap()];
    for _ in 0..DEPTH {
        let last = fds.last().unwrap();
        mkdirat(last, "d", Mode::from_raw_mode(0o755)).unwrap();
        let next = openat(last, "d", dir, Mode::empty()).unwrap();
        fds.push(next);
    }
    let leaf = openat(
        fds.last().unwrap(),
        "leaf",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .unwrap();
    rustix::io::write(&leaf, b"x").unwrap();
    drop(leaf);

    // A child process, so a stack overflow fails this test, not the binary.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ext"))
        .env_remove("EXTANT_DIR")
        .arg("--d")
        .arg(e.base.join("store"))
        .arg("check")
        .output()
        .unwrap();

    // Bottom-up cleanup by fd; the temp dir's own recursive removal would
    // hit the same depth.
    unlinkat(fds.last().unwrap(), "leaf", AtFlags::empty()).unwrap();
    for i in (0..DEPTH).rev() {
        unlinkat(&fds[i], "d", AtFlags::REMOVEDIR).unwrap();
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{:?} {}",
        out.status,
        &stderr[..stderr.len().min(300)]
    );
    assert!(
        stdout.starts_with("NEW\t") && stdout.trim_end().ends_with("/leaf"),
        "{}",
        &stdout[..stdout.len().min(300)]
    );
}
