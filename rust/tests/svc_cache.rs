//! The blob cache at library level: crash-state invariants through the step
//! executor (ES-8, ES-25), eviction against a reference model (ES-26), the
//! ES-10 record test, ES-27 touch, ES-30 sweep and ES-24 names and modes.
//!
//! Run: `cargo test --test svc_cache`. All tests here run under umask 0, so a
//! file created with default modes shows up as world-writable.

mod svc;

use ext::cache::{Cache, Effect, FsExecutor, Record, StepExecutor, Verified};
use ext::digest::{Digest, Enc};
use ext::store::Store;
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Once};
use std::time::{Duration, SystemTime};
use svc::*;

fn umask0() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        rustix::process::umask(rustix::fs::Mode::empty());
    });
}

struct Fixture {
    _t: tempfile::TempDir,
    dir: PathBuf,
    store: Store,
}

fn fixture() -> Fixture {
    umask0();
    let t = tempfile::tempdir().unwrap();
    // tempfile relies on the umask for the directory mode.
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let dir = fs::canonicalize(t.path()).unwrap().join("store");
    let store = Store::init_bare(&dir).unwrap();
    Fixture { _t: t, dir, store }
}

/// A candidate in `cache/tmp/` that verified against its own digest.
fn verified(cache: &Cache, content: &[u8]) -> Verified {
    let mut tmp = cache.create_tmp().expect("tmp file");
    tmp.file().write_all(content).unwrap();
    Verified::check(tmp, &fetchable(content)).expect("honest content verifies")
}

/// Drops effect `at` and everything after it, silently, including the
/// implementation's own cleanup: a killed process. Logs what ran.
struct Crash<'a> {
    inner: FsExecutor<'a>,
    at: usize,
    seen: usize,
    log: Vec<&'static str>,
}

impl<'a> Crash<'a> {
    fn new(store: &'a Store, at: usize) -> Crash<'a> {
        Crash {
            inner: FsExecutor { store },
            at,
            seen: 0,
            log: vec![],
        }
    }
}

fn kind(e: &Effect) -> &'static str {
    match e {
        Effect::Write { .. } => "write",
        Effect::Fsync { .. } => "fsync",
        Effect::Rename { .. } => "rename",
        Effect::Commit { .. } => "commit",
        Effect::Unlink { .. } => "unlink",
    }
}

impl StepExecutor for Crash<'_> {
    fn step(&mut self, e: &Effect) -> std::io::Result<()> {
        self.seen += 1;
        if self.seen > self.at {
            return Ok(());
        }
        self.inner.step(e)?;
        self.log.push(kind(e));
        Ok(())
    }
}

fn hex_name(d: &Digest) -> String {
    d.encode(Enc::Hex)
}

/// F1, F2 and F10 on disk: every record has a regular file of its size whose
/// independently computed hash is its name, and no final-named file anywhere
/// has a name that differs from its hash. Orphans (file, no record) are legal.
fn assert_cache_invariants(f: &Fixture) {
    let store = Store::open(&f.dir).unwrap();
    let cache = Cache::new(&store, u64::MAX);
    for r in cache.records().unwrap() {
        let p = f.dir.join("cache/SHA-256").join(hex_name(&r.digest));
        let data = fs::read(&p)
            .unwrap_or_else(|e| panic!("F1: record {} without file: {e}", hex_name(&r.digest)));
        assert_eq!(data.len() as u64, r.size, "record size vs file size");
        assert_eq!(
            sha256_hex(&data),
            hex_name(&r.digest),
            "F2: file does not hash to its name"
        );
    }
    if let Ok(rd) = fs::read_dir(f.dir.join("cache/SHA-256")) {
        for e in rd.flatten() {
            let data = fs::read(e.path()).unwrap();
            assert_eq!(
                sha256_hex(&data),
                e.file_name().to_string_lossy(),
                "F10: final name with other content"
            );
        }
    }
}

// ----------------------------------------------------------- ES-8, ES-25 ----

/// ES-8, ES-25, F1, F10. Admit is killed before each of its effects in turn:
/// every intermediate state satisfies the invariants, the effects run in the
/// required order, and a later uncrashed admit converges to one record.
/// Violators: record inserted before the rename (red when killed between),
/// rename before fsync (red on order), the final name written then verified.
#[test]
fn admit_killed_at_any_effect_leaves_a_consistent_cache() {
    for content in [blob(0, 1), blob(1, 1), blob(4097, 2)] {
        let order = ["fsync", "rename", "commit"];
        let n = {
            let f = fixture();
            let cache = Cache::new(&f.store, 1 << 20);
            let lock = f.store.lock().unwrap();
            let mut ex = Crash::new(&f.store, usize::MAX);
            cache
                .admit(&lock, &mut ex, verified(&cache, &content), 10)
                .expect("admit");
            assert_eq!(ex.log, order, "admit effects, in program order");
            drop(lock);
            assert_cache_invariants(&f);
            assert_eq!(cache.records().unwrap().len(), 1);
            ex.log.len()
        };
        for k in 0..n {
            let f = fixture();
            let cache = Cache::new(&f.store, 1 << 20);
            let lock = f.store.lock().unwrap();
            let mut ex = Crash::new(&f.store, k);
            let _ = cache.admit(&lock, &mut ex, verified(&cache, &content), 10);
            assert_eq!(ex.log, order[..k], "killed before effect {k}");
            drop(lock);
            assert_cache_invariants(&f);
            // The next run (sweep is part of admit) must converge.
            let lock = f.store.lock().unwrap();
            let mut fs_ex = FsExecutor { store: &f.store };
            cache
                .admit(&lock, &mut fs_ex, verified(&cache, &content), 11)
                .expect("recovery admit");
            drop(lock);
            assert_cache_invariants(&f);
            assert_eq!(
                cache.records().unwrap().len(),
                1,
                "killed at {k}: one record after recovery"
            );
        }
    }
}

/// ES-25 for eviction: record delete is committed before the file is
/// unlinked, so a kill between leaves an orphan, never a dangling record.
/// Violator: unlink first, then delete the record.
#[test]
fn eviction_killed_at_any_effect_never_leaves_a_dangling_record() {
    let (a, b) = (blob(10, 1), blob(10, 2));
    let probe = |at: usize| {
        let f = fixture();
        let cache = Cache::new(&f.store, 15); // room for one
        let lock = f.store.lock().unwrap();
        let mut fs_ex = FsExecutor { store: &f.store };
        cache
            .admit(&lock, &mut fs_ex, verified(&cache, &a), 1)
            .unwrap();
        let mut ex = Crash::new(&f.store, at);
        let _ = cache.admit(&lock, &mut ex, verified(&cache, &b), 2);
        drop(lock);
        assert_cache_invariants(&f);
        (ex.log.clone(), cache.records().unwrap(), f)
    };
    let (full, recs, f) = probe(usize::MAX);
    assert_eq!(
        full,
        ["fsync", "rename", "commit", "unlink"],
        "evicted file is unlinked after the commit"
    );
    assert_eq!(
        recs.iter().map(|r| r.digest.clone()).collect::<Vec<_>>(),
        [digest_of(&b)]
    );
    assert!(!f
        .dir
        .join("cache/SHA-256")
        .join(hex_name(&digest_of(&a)))
        .exists());
    for k in 0..full.len() {
        probe(k);
    }
}

// ----------------------------------------------------------------- ES-26 ----

#[derive(Clone, Debug)]
enum Op {
    Admit(usize),
    Touch(usize, u8), // now = running max minus this much, saturating
}

/// Replays `ops` against the cache and a reference model and compares the
/// resident set after every operation. `sizes[i]` is the size of blob i.
fn check_model(cap: u64, sizes: &[usize], ops: &[Op], ties: bool) {
    let f = fixture();
    let cache = Cache::new(&f.store, cap);
    let blobs: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(i, n)| blob(*n, 40 + i as u8))
        .collect();
    let digests: Vec<Digest> = blobs.iter().map(|b| digest_of(b)).collect();
    let mut model: BTreeMap<Digest, (u64, i64)> = BTreeMap::new();
    let mut clock = 1_000i64;
    for op in ops {
        match op {
            Op::Admit(i) => {
                if !ties {
                    clock += 1;
                }
                let lock = f.store.lock().unwrap();
                let mut ex = FsExecutor { store: &f.store };
                cache
                    .admit(&lock, &mut ex, verified(&cache, &blobs[*i]), clock)
                    .unwrap();
                drop(lock);
                let e = model
                    .entry(digests[*i].clone())
                    .or_insert((sizes[*i] as u64, clock));
                e.1 = e.1.max(clock);
                // Reference eviction: oldest (atime, digest) first, never the new one.
                while model.values().map(|v| v.0).sum::<u64>() > cap {
                    let victim = model
                        .iter()
                        .filter(|(d, _)| **d != digests[*i])
                        .min_by(|a, b| (a.1 .1, a.0).cmp(&(b.1 .1, b.0)))
                        .map(|(d, _)| d.clone())
                        .expect("a blob larger than the capacity cannot occur");
                    model.remove(&victim);
                }
            }
            Op::Touch(i, back) => {
                let now = clock - i64::from(*back);
                // Touching a digest that is not resident is not what this checks.
                let _ = cache.touch(&digests[*i], now);
                if let Some(e) = model.get_mut(&digests[*i]) {
                    e.1 = e.1.max(now);
                }
            }
        }
        let mut got: Vec<Record> = cache.records().unwrap();
        got.sort_by(|a, b| a.digest.cmp(&b.digest));
        let want: Vec<Record> = model
            .iter()
            .map(|(d, (s, a))| Record {
                digest: d.clone(),
                size: *s,
                atime_ns: *a,
            })
            .collect();
        assert_eq!(got, want, "after {op:?}");
        assert!(got.iter().map(|r| r.size).sum::<u64>() <= cap);
        assert_cache_invariants(&f);
        let files = fs::read_dir(f.dir.join("cache/SHA-256"))
            .map(|rd| rd.count())
            .unwrap_or(0);
        assert_eq!(files, got.len(), "files on disk equal records");
    }
}

fn ops(ids: usize) -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(
        prop_oneof![
            3 => (0..ids).prop_map(Op::Admit),
            2 => (0..ids, 0u8..40).prop_map(|(i, b)| Op::Touch(i, b)),
        ],
        1..24,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    /// ES-26 against a reference model, with forced equal atimes (the tie-break
    /// is the only thing ordering them), backward touch clocks and
    /// re-admission. Violators: eviction by insertion order, ignoring the
    /// digest tie-break, over-evicting, evicting the blob just admitted,
    /// ignoring the capacity.
    #[test]
    fn resident_set_equals_the_reference_model(
        sizes in prop::collection::vec(1usize..40, 4),
        ops in ops(4),
        ties in any::<bool>(),
    ) {
        check_model(60, &sizes, &ops, ties);
    }
}

/// ES-26 mandatory boundaries: capacity 1 byte, a blob exactly the capacity
/// (it must push out everything else), and the empty blob (size 0 costs
/// nothing and is never a victim that matters).
#[test]
fn eviction_boundaries() {
    use Op::*;
    check_model(
        1,
        &[1, 1, 1],
        &[Admit(0), Admit(1), Admit(0), Admit(2)],
        false,
    );
    check_model(
        50,
        &[10, 10, 50, 10],
        &[Admit(0), Admit(1), Admit(2), Admit(3)],
        false,
    );
    check_model(
        10,
        &[10, 10],
        &[Admit(0), Touch(0, 5), Admit(1), Admit(0)],
        true,
    );
}

#[test]
fn the_empty_blob_is_cacheable_and_free() {
    let f = fixture();
    let cache = Cache::new(&f.store, 5);
    let lock = f.store.lock().unwrap();
    let mut ex = FsExecutor { store: &f.store };
    cache
        .admit(&lock, &mut ex, verified(&cache, b""), 1)
        .unwrap();
    cache
        .admit(&lock, &mut ex, verified(&cache, &blob(5, 3)), 2)
        .unwrap();
    drop(lock);
    let sizes: Vec<u64> = cache.records().unwrap().iter().map(|r| r.size).collect();
    assert_eq!(
        sizes.len(),
        2,
        "a zero-size record does not count against the capacity: {sizes:?}"
    );
    assert_cache_invariants(&f);
}

// ----------------------------------------------------------------- ES-10 ----

/// Runs `f` on another thread while this one holds the store lock, and fails
/// if it does not finish in time: the shape of "must not wait on the lock".
fn while_locked<T: Send>(store: &Store, f: impl FnOnce() -> T + Send) -> T {
    let lock = store.lock().unwrap();
    std::thread::scope(|s| {
        let (tx, rx) = mpsc::channel();
        s.spawn(move || tx.send(f()).ok());
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(v) => {
                drop(lock);
                v
            }
            Err(_) => {
                drop(lock); // let the blocked thread finish so the scope can end
                panic!("blocked on the store lock for 2 s");
            }
        }
    })
}

/// ES-10 and ES-27. A cache record answers only through a regular file of the
/// recorded size, opened without following symlinks; the rest is a miss that
/// evicts when the lock is free. `resolve` does not hash. Violators: trusting
/// the record blindly, following a symlink (and deleting its target),
/// hashing on lookup (red on `same size, other bytes`), evicting without the
/// lock, or waiting for a busy lock.
#[test]
fn cache_lookup_requires_a_regular_file_of_the_recorded_size() {
    type Tamper = fn(&Path, &Path);
    let cases: Vec<(&str, Tamper, bool)> = vec![
        ("intact", |_, _| {}, true),
        (
            "same size, other bytes",
            |p, _| fs::write(p, blob(100, 99)).unwrap(),
            true,
        ),
        ("missing", |p, _| fs::remove_file(p).unwrap(), false),
        (
            "wrong size",
            |p, _| fs::write(p, blob(99, 1)).unwrap(),
            false,
        ),
        (
            "symlink to a right-size file",
            |p, aside| {
                fs::write(aside, blob(100, 1)).unwrap();
                fs::remove_file(p).unwrap();
                symlink(aside, p).unwrap();
            },
            false,
        ),
        (
            "directory",
            |p, _| {
                fs::remove_file(p).unwrap();
                fs::create_dir(p).unwrap();
            },
            false,
        ),
    ];
    for (name, tamper, hit) in cases {
        let f = fixture();
        let cache = Cache::new(&f.store, 1 << 20);
        let content = blob(100, 1);
        let d = digest_of(&content);
        let lock = f.store.lock().unwrap();
        let mut ex = FsExecutor { store: &f.store };
        cache
            .admit(&lock, &mut ex, verified(&cache, &content), 1)
            .unwrap();
        drop(lock);
        let file = f.dir.join("cache/SHA-256").join(hex_name(&d));
        let aside = f.dir.join("aside");
        tamper(&file, &aside);
        let aside_existed = aside.exists();

        // A busy lock: a miss, no eviction, no wait.
        if !hit {
            let got = while_locked(&f.store, || {
                cache
                    .lookup(&d, &mut FsExecutor { store: &f.store })
                    .unwrap()
            });
            assert!(got.is_none(), "{name}: busy lock");
            assert_eq!(
                cache.records().unwrap().len(),
                1,
                "{name}: not evicted while the lock is busy"
            );
        }
        let got = cache
            .lookup(&d, &mut FsExecutor { store: &f.store })
            .unwrap();
        if hit {
            assert_eq!(
                got.map(|f| f.metadata().unwrap().ino()),
                Some(fs::metadata(&file).unwrap().ino()),
                "{name}"
            );
            assert_eq!(cache.records().unwrap().len(), 1);
        } else {
            assert!(got.is_none(), "{name}");
            assert!(
                cache.records().unwrap().is_empty(),
                "{name}: record evicted"
            );
            if name == "directory" {
                assert!(file.is_dir(), "{name}: the directory is left in place");
            } else {
                assert!(fs::symlink_metadata(&file).is_err(), "{name}: file evicted");
            }
            if aside_existed {
                assert!(
                    aside.exists(),
                    "{name}: a symlink's target is never touched"
                );
            }
        }
    }
}

// ----------------------------------------------------------------- ES-27 ----

/// ES-27. `atime := max(now, atime)` for touch and re-admission, and a touch against a busy lock is
/// skipped immediately. Violators: `atime := now` (a backward clock lowers
/// it), blocking acquisition, failing the lookup on a busy lock.
#[test]
fn touch_is_monotone_and_never_waits() {
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    let content = blob(8, 1);
    let d = digest_of(&content);
    let lock = f.store.lock().unwrap();
    cache
        .admit(
            &lock,
            &mut FsExecutor { store: &f.store },
            verified(&cache, &content),
            500,
        )
        .unwrap();
    drop(lock);
    let atime = || cache.records().unwrap()[0].atime_ns;
    // The lock is free here, but a `sha256sum` spawned by a parallel test
    // inherits this process's lock descriptor until it execs, which can hold
    // the flock for a moment after `drop(lock)`. A touch that skips then is
    // correct (ES-27), so retry a bounded number of times and require that
    // the touch ran: an assertion after a skipped touch would prove nothing.
    let touched = |d: &Digest, now: i64| {
        for _ in 0..500 {
            if cache.touch(d, now).unwrap() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the free lock never became available to touch");
    };
    touched(&d, 900);
    assert_eq!(atime(), 900);
    touched(&d, 100);
    assert_eq!(atime(), 900, "a touch never lowers atime");
    // Touching a digest that is not resident is a no-op, not an error.
    let before = cache.records().unwrap();
    touched(&digest_of(b"absent"), 7_000);
    assert_eq!(cache.records().unwrap(), before);
    // Re-admission keeps atime := max(old, now), even with a backward clock.
    let lock = f.store.lock().unwrap();
    cache
        .admit(
            &lock,
            &mut FsExecutor { store: &f.store },
            verified(&cache, &content),
            100,
        )
        .unwrap();
    drop(lock);
    assert_eq!(
        atime(),
        900,
        "re-admission with an older clock does not lower atime"
    );
    let skipped = while_locked(&f.store, || cache.touch(&d, 5_000).unwrap());
    assert!(!skipped, "busy lock: skipped, reported");
    assert_eq!(atime(), 900);
}

// ----------------------------------------------------------------- ES-30 ----

fn backdate(p: &Path, secs: u64) {
    let f = fs::OpenOptions::new().write(true).open(p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(secs))
        .unwrap();
}

/// ES-30. Sweep removes orphans and unlocked temporaries older than 60 s, and
/// keeps a young one and a live (locked) one even when its mtime is old: the
/// flock protects it, not the age. Violators: deleting by age alone (the live
/// backdated file disappears), deleting every temporary, never sweeping.
#[test]
fn sweep_removes_the_dead_and_keeps_the_live() {
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    let keep = blob(20, 1);
    let lock = f.store.lock().unwrap();
    cache
        .admit(
            &lock,
            &mut FsExecutor { store: &f.store },
            verified(&cache, &keep),
            1,
        )
        .unwrap();
    drop(lock);

    let tmp = f.dir.join("cache/tmp");
    let orphan = f
        .dir
        .join("cache/SHA-256")
        .join(hex_name(&digest_of(b"orphan")));
    fs::write(&orphan, b"orphan").unwrap();
    // Locked by another open file description, as a running fetch's file is.
    let live_path = tmp.join("live");
    let live = fs::File::create(&live_path).unwrap();
    rustix::fs::flock(&live, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    backdate(&live_path, 300);
    let young = tmp.join("young");
    let old = tmp.join("old");
    fs::write(&young, b"y").unwrap();
    fs::write(&old, b"o").unwrap();
    backdate(&old, 300);

    let sweep = |cache: &Cache| {
        let lock = f.store.lock().unwrap();
        cache
            .sweep(
                &lock,
                &mut FsExecutor { store: &f.store },
                SystemTime::now(),
            )
            .unwrap();
    };
    sweep(&cache);
    assert!(!orphan.exists(), "orphan file removed");
    assert!(!old.exists(), "unlocked stale temporary removed");
    assert!(
        young.exists(),
        "a temporary younger than 60 s survives (create-then-lock window)"
    );
    assert!(
        live_path.exists(),
        "a locked temporary survives whatever its age"
    );
    assert_eq!(cache.records().unwrap().len(), 1);
    assert_cache_invariants(&f);

    // The fetch dies (its lock goes with it); once old enough the file is dead.
    let dead = live_path.clone();
    drop(live); // closing releases the flock, as a dying process does
    sweep(&cache);
    assert!(
        !dead.exists(),
        "after its owner died, the old temporary is removed"
    );
    assert!(young.exists());
}

/// ES-30: sweep runs at the start of every admit, so a dead temporary and an
/// orphan are gone after an unrelated admit. Violator: sweep never invoked
/// from admit.
#[test]
fn admit_sweeps_first() {
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    let lock = f.store.lock().unwrap();
    let mut ex = FsExecutor { store: &f.store };
    cache
        .admit(&lock, &mut ex, verified(&cache, &blob(5, 1)), 1)
        .unwrap();
    let orphan = f
        .dir
        .join("cache/SHA-256")
        .join(hex_name(&digest_of(b"orphan")));
    fs::write(&orphan, b"orphan").unwrap();
    let old = f.dir.join("cache/tmp/old");
    fs::write(&old, b"o").unwrap();
    backdate(&old, 300);
    cache
        .admit(&lock, &mut ex, verified(&cache, &blob(5, 2)), 2)
        .unwrap();
    assert!(
        !orphan.exists() && !old.exists(),
        "dead files survived an admit"
    );
}

// ----------------------------------------------------------------- ES-24 ----

/// ES-24 under umask 0. Directories 0700, files 0600 with explicit modes, and
/// the final name is a function of the digest alone, uppercase hex. Violators:
/// default modes (0777/0666 under this umask), lowercase hex, any name from
/// other data.
#[test]
fn cache_paths_and_modes_are_explicit() {
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    let content = b"abc".to_vec();
    let mut tmp = cache.create_tmp().unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(tmp.path()), 0o600, "in-flight file");
    // The in-flight file is flocked for its fetch's life (ES-30 relies on it).
    let other = fs::File::open(tmp.path()).unwrap();
    assert!(
        rustix::fs::flock(&other, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err(),
        "create_tmp must return a locked file"
    );
    let _ = tmp.file();
    drop(other);
    drop(tmp);
    assert!(
        f.dir.join("cache/tmp").read_dir().unwrap().next().is_none(),
        "dropping an unpersisted TmpFile deletes it"
    );
    let lock = f.store.lock().unwrap();
    cache
        .admit(
            &lock,
            &mut FsExecutor { store: &f.store },
            verified(&cache, &content),
            1,
        )
        .unwrap();
    drop(lock);
    let rel = Cache::relative_path(&digest_of(&content));
    assert_eq!(
        rel,
        Path::new("cache/SHA-256/BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
    );
    let final_path = f.dir.join(&rel);
    assert_eq!(mode(&final_path), 0o600);
    for d in ["cache", "cache/SHA-256", "cache/tmp"] {
        assert_eq!(mode(&f.dir.join(d)), 0o700, "{d}");
    }
}

// ------------------------------------------------------- ES-22, F10 ----

/// F10 for the services file, deterministically: `write_file` killed before
/// each of its effects leaves exactly the old bytes or exactly the new ones,
/// never a mixture, and the effects are a write to a store-local temporary
/// followed (last) by a rename onto `services`. A killed process may leave a
/// temporary (cleanup is dropped with everything else); the next write must
/// succeed and leave none. Violators: truncate-then-write on the final name,
/// renaming before the content is written, a temporary outside the store.
#[test]
fn services_file_write_is_atomic_at_every_kill_point() {
    use ext::services::{write_file, ServiceUri};
    let uris = |n: std::ops::Range<usize>| -> Vec<ServiceUri> {
        n.map(|i| ServiceUri::parse(&format!("https://h{i}.example/")).unwrap())
            .collect()
    };
    let (old, new) = (uris(0..3), uris(0..5));
    let (old_b, new_b) = (
        ext::services::render_file(&old),
        ext::services::render_file(&new),
    );
    let run = |at: usize| {
        let f = fixture();
        let lock = f.store.lock().unwrap();
        write_file(&f.store, &lock, &mut FsExecutor { store: &f.store }, &old).unwrap();
        let mut ex = Crash::new(&f.store, at);
        let _ = write_file(&f.store, &lock, &mut ex, &new);
        let got = fs::read(f.dir.join("services")).unwrap();
        assert!(
            got == old_b || got == new_b,
            "killed at {at}: a mixed services file {got:?}"
        );
        let log = ex.log.clone();
        drop(ex);
        (f, lock, log)
    };
    let listing = |d: &Path| -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };
    let (f0, _l, full) = run(usize::MAX);
    let baseline = listing(&f0.dir);
    assert!(
        full.len() >= 2
            && full[0] == "write"
            && *full.last().unwrap() == "rename"
            && full
                .iter()
                .all(|k| ["write", "fsync", "rename"].contains(k)),
        "{full:?}"
    );
    for k in 0..full.len() {
        let (f, lock, log) = run(k);
        assert_eq!(log, full[..k]);
        assert_eq!(
            fs::read(f.dir.join("services")).unwrap(),
            old_b,
            "killed before effect {k}: not yet renamed, so the old bytes"
        );
        write_file(&f.store, &lock, &mut FsExecutor { store: &f.store }, &new).unwrap();
        assert_eq!(fs::read(f.dir.join("services")).unwrap(), new_b);
        assert_eq!(
            listing(&f.dir),
            baseline,
            "a temporary survived the next write"
        );
    }
}

// ----------------------------------------------- surviving-mutant relations ----

/// ES-30. A fresh store has no `cache/` yet; sweeping it is a no-op, not an
/// error (every first admit sweeps first). Violator: treating an absent
/// directory as a read failure.
#[test]
fn sweeping_a_store_with_no_cache_yet_is_a_no_op() {
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    let lock = f.store.lock().unwrap();
    cache
        .sweep(
            &lock,
            &mut FsExecutor { store: &f.store },
            SystemTime::now(),
        )
        .expect("nothing to sweep is not a failure");
}

/// ES-25 and ES-26. Eviction is the commit then the unlink, and a kill between
/// them leaves an orphan; running the eviction again (or evicting a blob whose
/// file is already gone) must still succeed and leave no record. Evict itself
/// must remove both record and file. Violators: evict doing nothing; an
/// absent file treated as a failure.
#[test]
fn evict_removes_record_and_file_and_tolerates_a_missing_file() {
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    let content = blob(30, 1);
    let d = digest_of(&content);
    let file = f.dir.join(Cache::relative_path(&d));
    let admit = |c: &[u8]| {
        let lock = f.store.lock().unwrap();
        let v = verified(&cache, c);
        cache
            .admit(&lock, &mut FsExecutor { store: &f.store }, v, 1)
            .unwrap();
    };
    admit(&content);
    let lock = f.store.lock().unwrap();
    let mut ex = Crash::new(&f.store, usize::MAX);
    cache.evict(&lock, &mut ex, &d).unwrap();
    assert_eq!(ex.log, ["commit", "unlink"]);
    drop(lock);
    assert!(cache.records().unwrap().is_empty() && !file.exists());

    admit(&content);
    fs::remove_file(&file).unwrap(); // the file vanished (an earlier kill, a sweep)
    let lock = f.store.lock().unwrap();
    cache
        .evict(&lock, &mut FsExecutor { store: &f.store }, &d)
        .expect("evicting a blob whose file is already gone");
    assert!(cache.records().unwrap().is_empty());
}

/// ES-29. Admit, evict and sweep act only under the lock of their own store: a
/// lock taken on another store excludes nothing here, so each refuses and
/// performs no effect. Violator: not checking whose lock it is.
#[test]
fn a_lock_from_another_store_authorises_nothing() {
    let (a, b) = (fixture(), fixture());
    let cache = Cache::new(&a.store, 1 << 20);
    let foreign = b.store.lock().unwrap();
    let content = blob(20, 1);
    let mut ex = Crash::new(&a.store, usize::MAX);
    assert!(cache
        .admit(&foreign, &mut ex, verified(&cache, &content), 1)
        .is_err());
    assert!(cache
        .evict(&foreign, &mut ex, &digest_of(&content))
        .is_err());
    assert!(cache.sweep(&foreign, &mut ex, SystemTime::now()).is_err());
    assert!(
        ex.log.is_empty(),
        "effects ran under a foreign lock: {:?}",
        ex.log
    );
    assert!(cache.records().unwrap().is_empty());
}

/// ES-26/ES-27. A newly admitted record's atime is its own clock, whatever
/// the other records hold; only re-admission of the same digest keeps the
/// larger of old and new. Violator: seeding the new atime from another
/// record.
#[test]
fn a_new_record_takes_its_own_clock() {
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    let (a, b) = (blob(10, 1), blob(10, 2));
    let admit = |c: &[u8], now: i64| {
        let lock = f.store.lock().unwrap();
        let v = verified(&cache, c);
        cache
            .admit(&lock, &mut FsExecutor { store: &f.store }, v, now)
            .unwrap();
    };
    admit(&a, 900);
    admit(&b, 100);
    admit(&a, 50);
    let mut got: Vec<(Digest, i64)> = cache
        .records()
        .unwrap()
        .into_iter()
        .map(|r| (r.digest, r.atime_ns))
        .collect();
    got.sort();
    let mut want = vec![(digest_of(&a), 900), (digest_of(&b), 100)];
    want.sort();
    assert_eq!(got, want);
}

/// No silent failures (ES-25): an unlink that fails for a reason other than
/// "already gone" is reported; a missing file is not a failure. Violator: an
/// executor that swallows every unlink error.
#[test]
fn unlink_reports_real_failures_but_not_absence() {
    let f = fixture();
    let mut ex = FsExecutor { store: &f.store };
    let dir = f.dir.join("a-directory");
    fs::create_dir(&dir).unwrap();
    assert!(ex.step(&Effect::Unlink { path: dir }).is_err());
    assert!(ex
        .step(&Effect::Unlink {
            path: f.dir.join("absent")
        })
        .is_ok());
}

/// ES-30. A cache directory that cannot be listed is an error, not "nothing
/// to sweep"; only an absent one is empty. Violator: swallowing every
/// read_dir failure, which would let a broken store skip its sweep silently.
#[test]
fn sweep_reports_an_unreadable_tmp_directory() {
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    fs::create_dir_all(f.dir.join("cache")).unwrap();
    fs::write(f.dir.join("cache/tmp"), b"not a directory").unwrap();
    let lock = f.store.lock().unwrap();
    assert!(cache
        .sweep(
            &lock,
            &mut FsExecutor { store: &f.store },
            SystemTime::now()
        )
        .is_err());
}

/// ES-25. A store that cannot hold the cache layout fails `create_tmp` up
/// front, before any bytes are fetched, whichever directory is the one that
/// cannot be made. Violator: swallowing a directory-creation error other than
/// "already exists", so the fetch runs and only the admit fails.
#[test]
fn create_tmp_fails_early_when_a_cache_directory_cannot_be_made() {
    if skip_if_root("mode bits do not stop uid 0") {
        return;
    }
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    drop(cache.create_tmp().unwrap()); // lays out cache/, cache/tmp, cache/SHA-256
    fs::remove_dir(f.dir.join("cache/SHA-256")).unwrap();
    fs::set_permissions(f.dir.join("cache"), fs::Permissions::from_mode(0o500)).unwrap();
    let r = cache.create_tmp();
    fs::set_permissions(f.dir.join("cache"), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        r.is_err(),
        "the SHA-256 directory could not be made yet a tmp file was handed out"
    );
}

/// ES-30, exactly at the age floor: "younger than 60 s" survives and "older"
/// goes, so a temporary of age exactly 60 s is not older and stays, and one
/// nanosecond later it is removed. Sweep takes `now`, so the boundary is
/// hit exactly (the mtime is read back from the file system). Violator:
/// `age >= 60 s`, which removes a file the spec says may not yet go.
#[test]
fn sweep_age_floor_is_strict() {
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    drop(cache.create_tmp().unwrap()); // lays out cache/tmp
    let p = f.dir.join("cache/tmp/aged");
    fs::write(&p, b"x").unwrap();
    let mtime = fs::metadata(&p).unwrap().modified().unwrap();
    let sweep = |now: SystemTime| {
        let lock = f.store.lock().unwrap();
        cache
            .sweep(&lock, &mut FsExecutor { store: &f.store }, now)
            .unwrap();
    };
    sweep(mtime + Duration::from_secs(60));
    assert!(p.exists(), "exactly 60 s old is not older than 60 s");
    sweep(mtime + Duration::from_secs(60) + Duration::from_nanos(1));
    assert!(!p.exists(), "60 s and 1 ns old is older");
}

// ------------------------------------------- unlink and discard failures ----

/// Runs every effect for real except `Unlink`/`Commit` of the chosen kind
/// when the target's file name is in `fail`, which reports EACCES without
/// doing it: an unlink the OS refuses, or a commit that cannot be made.
struct Refuse<'a> {
    inner: FsExecutor<'a>,
    kind: &'static str,
    fail: Vec<String>,
    refused: usize,
}

impl<'a> Refuse<'a> {
    fn new(store: &'a Store, kind: &'static str, fail: Vec<String>) -> Refuse<'a> {
        Refuse {
            inner: FsExecutor { store },
            kind,
            fail,
            refused: 0,
        }
    }
}

impl StepExecutor for Refuse<'_> {
    fn step(&mut self, e: &Effect) -> std::io::Result<()> {
        let hit = match e {
            Effect::Unlink { path } if self.kind == "unlink" => self
                .fail
                .iter()
                .any(|n| path.file_name().is_some_and(|f| f == n.as_str())),
            // A commit has no path; `fail` non-empty means "refuse it".
            Effect::Commit { .. } if self.kind == "commit" => !self.fail.is_empty(),
            _ => false,
        };
        if hit {
            self.refused += 1;
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        self.inner.step(e)
    }
}

/// ES-26: "modulo orphans left by a failed unlink and swept at the next
/// admit." The commit is the point of no return; an unlink the OS refuses
/// afterwards leaves an orphan and must not turn a committed admission into
/// an error. Over every subset of three victims whose unlink fails: admit is
/// Ok, exactly the new record remains, its file is present, the refused
/// victims' files are the orphans and the others are gone, and the on-disk
/// invariants hold. Violator: `ex.step(Unlink)?` after the commit.
#[test]
fn a_refused_unlink_after_the_commit_leaves_an_orphan_not_an_error() {
    let olds: Vec<Vec<u8>> = (0..3).map(|i| blob(10, 10 + i)).collect();
    let new = blob(30, 99);
    for mask in 1u8..8 {
        let f = fixture();
        let cache = Cache::new(&f.store, 35); // 30 + one old would be 40: all three go
        let lock = f.store.lock().unwrap();
        let mut fs_ex = FsExecutor { store: &f.store };
        for (i, o) in olds.iter().enumerate() {
            cache
                .admit(&lock, &mut fs_ex, verified(&cache, o), 1 + i as i64)
                .unwrap();
        }
        let refused: Vec<String> = (0..3)
            .filter(|i| mask >> i & 1 == 1)
            .map(|i| hex_name(&digest_of(&olds[i])))
            .collect();
        let mut ex = Refuse::new(&f.store, "unlink", refused.clone());
        let r = cache.admit(&lock, &mut ex, verified(&cache, &new), 10);
        assert!(
            r.is_ok(),
            "mask {mask:03b}: a failed victim unlink failed the committed admit: {r:?}"
        );
        assert_eq!(ex.refused, refused.len(), "mask {mask:03b}: setup");
        drop(lock);
        let recs = cache.records().unwrap();
        assert_eq!(
            recs.iter().map(|r| r.digest.clone()).collect::<Vec<_>>(),
            [digest_of(&new)],
            "mask {mask:03b}"
        );
        let dir = f.dir.join("cache/SHA-256");
        assert!(dir.join(hex_name(&digest_of(&new))).is_file());
        for o in &olds {
            let n = hex_name(&digest_of(o));
            assert_eq!(
                dir.join(&n).exists(),
                refused.contains(&n),
                "mask {mask:03b}: only refused victims remain, as orphans"
            );
        }
        assert_cache_invariants(&f);
    }
}

/// ES-25 and ES-26 for `evict`: the record delete is committed, so a refused
/// unlink is an orphan, not an error. Violator: `ex.step(Unlink)?`.
#[test]
fn evict_with_a_refused_unlink_still_succeeds() {
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    let content = blob(30, 1);
    let d = digest_of(&content);
    let lock = f.store.lock().unwrap();
    cache
        .admit(
            &lock,
            &mut FsExecutor { store: &f.store },
            verified(&cache, &content),
            1,
        )
        .unwrap();
    let mut ex = Refuse::new(&f.store, "unlink", vec![hex_name(&d)]);
    let r = cache.evict(&lock, &mut ex, &d);
    assert!(r.is_ok(), "committed eviction reported as failed: {r:?}");
    assert_eq!(ex.refused, 1, "setup");
    assert!(cache.records().unwrap().is_empty());
    assert!(f.dir.join(Cache::relative_path(&d)).exists(), "the orphan");
}

/// ES-10: "Otherwise the record is removed when the lock is available ...
/// the lookup continues as a miss." Removal is best effort: a stale record
/// whose removal fails (the commit or the unlink refused) is still a miss,
/// never an error. Violator: `discard_if_free(..)?` in `lookup`.
#[test]
fn a_stale_record_whose_removal_fails_is_still_a_miss() {
    type Tamper = fn(&Path, &Path);
    let stale: Vec<(&str, Tamper)> = vec![
        ("wrong size", |p, _| fs::write(p, blob(99, 1)).unwrap()),
        ("missing", |p, _| fs::remove_file(p).unwrap()),
        ("symlink", |p, aside| {
            fs::write(aside, blob(100, 1)).unwrap();
            fs::remove_file(p).unwrap();
            symlink(aside, p).unwrap();
        }),
    ];
    for (name, tamper) in stale {
        for kind in ["commit", "unlink"] {
            let f = fixture();
            let cache = Cache::new(&f.store, 1 << 20);
            let content = blob(100, 1);
            let d = digest_of(&content);
            let lock = f.store.lock().unwrap();
            cache
                .admit(
                    &lock,
                    &mut FsExecutor { store: &f.store },
                    verified(&cache, &content),
                    1,
                )
                .unwrap();
            drop(lock);
            tamper(&f.dir.join(Cache::relative_path(&d)), &f.dir.join("aside"));
            let mut ex = Refuse::new(&f.store, kind, vec![hex_name(&d)]);
            let got = cache.lookup(&d, &mut ex);
            assert!(
                matches!(got, Ok(None)),
                "{name}, {kind} refused: expected a miss, got {got:?}"
            );
        }
    }
}

/// ES-10: "`ext` never deletes recursively or opens special files." A FIFO
/// stands where the record's file should be. Opening it for reading, even
/// non-blocking, releases a writer blocked in `open(O_WRONLY)`, so the
/// writer's open completing is the observable of an open. Violator: opening
/// the path before checking that it is a regular file.
#[test]
fn lookup_does_not_open_a_fifo() {
    let f = fixture();
    let cache = Cache::new(&f.store, 1 << 20);
    let content = blob(100, 1);
    let d = digest_of(&content);
    let lock = f.store.lock().unwrap();
    cache
        .admit(
            &lock,
            &mut FsExecutor { store: &f.store },
            verified(&cache, &content),
            1,
        )
        .unwrap();
    drop(lock);
    let file = f.dir.join(Cache::relative_path(&d));
    fs::remove_file(&file).unwrap();
    let c = std::ffi::CString::new(file.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "setup");

    let (tx, rx) = mpsc::channel();
    let p = file.clone();
    let writer = std::thread::spawn(move || {
        let w = fs::OpenOptions::new().write(true).open(&p);
        tx.send(w.is_ok()).ok();
        drop(w);
    });
    std::thread::sleep(Duration::from_millis(300)); // let the writer block in open
    let got = cache.lookup(&d, &mut FsExecutor { store: &f.store });
    let opened = rx.recv_timeout(Duration::from_millis(300)).is_ok();
    // Release the writer if lookup did not, so the thread ends either way.
    let _ = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&file);
    writer.join().unwrap();
    assert!(!opened, "lookup opened the FIFO (a reader appeared)");
    assert!(matches!(got, Ok(None)), "a FIFO is a miss");
}

/// ES-30 with ES-26: sweep runs at the start of every admit, and an orphan
/// is nothing worse than a leftover. Two record-less files and two dead
/// temporaries exist; over every non-empty subset whose unlink the OS
/// refuses, admit still succeeds and records the new blob, the refused
/// entries stay in place and the others are swept. Violator: `ex.step(Unlink)?`
/// in `sweep`, which lets one stubborn orphan fail every later admit.
#[test]
fn a_sweep_that_cannot_remove_an_orphan_leaves_it_and_admits() {
    let new = blob(30, 99);
    for mask in 1u8..16 {
        let f = fixture();
        let cache = Cache::new(&f.store, 1 << 20);
        let lock = f.store.lock().unwrap();
        // Seed the directories, then plant the sweepable entries.
        let seed = blob(5, 1);
        cache
            .admit(
                &lock,
                &mut FsExecutor { store: &f.store },
                verified(&cache, &seed),
                1,
            )
            .unwrap();
        let mut planted: Vec<PathBuf> = vec![];
        for i in 0..2u8 {
            let content = blob(7, 40 + i);
            let p = f
                .dir
                .join("cache/SHA-256")
                .join(hex_name(&digest_of(&content)));
            fs::write(&p, content).unwrap();
            planted.push(p);
        }
        for i in 0..2 {
            let p = f.dir.join("cache/tmp").join(format!("dead{i}"));
            fs::write(&p, b"x").unwrap();
            backdate(&p, 300);
            planted.push(p);
        }
        let refused: Vec<usize> = (0..4).filter(|i| mask >> i & 1 == 1).collect();
        let names = refused
            .iter()
            .map(|&i| {
                planted[i]
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        let mut ex = Refuse::new(&f.store, "unlink", names);
        let r = cache.admit(&lock, &mut ex, verified(&cache, &new), 10);
        assert!(
            r.is_ok(),
            "mask {mask:04b}: an unremovable orphan failed the admit: {r:?}"
        );
        assert_eq!(ex.refused, refused.len(), "mask {mask:04b}: setup");
        drop(lock);
        assert!(cache
            .records()
            .unwrap()
            .iter()
            .any(|r| r.digest == digest_of(&new)));
        for (i, p) in planted.iter().enumerate() {
            assert_eq!(
                p.exists(),
                refused.contains(&i),
                "mask {mask:04b}: {} should be {}",
                p.display(),
                if refused.contains(&i) {
                    "left"
                } else {
                    "swept"
                }
            );
        }
        assert_cache_invariants(&f);
    }
}
