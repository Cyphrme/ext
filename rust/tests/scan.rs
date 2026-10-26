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
    fs::create_dir_all(e.root.join("d/.ext")).unwrap();
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
