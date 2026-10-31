//! Plan amendment R5: `Index::batch` is one BEGIN IMMEDIATE transaction.

mod support;
use ext::digest::{Alg, Digest};
use ext::index::{Entry, Index, Meta};
use ext::store::{Store, StoreError};

fn entry(i: usize) -> Entry {
    Entry {
        path: format!("/r/f{i:05}").into_bytes(),
        digest: Digest::compute(Alg::Sha256, &i.to_le_bytes()),
        meta: Meta {
            size: 8,
            mtime_ns: 1,
            ctime_ns: 2,
            dev: 3,
            ino: i as u64,
        },
        last_checked_ns: 4,
    }
}

fn fresh() -> (tempfile::TempDir, Store, Index) {
    let (t, d) = support::canon_tmp();
    let st = Store::init_bare(&d.join("s")).unwrap();
    let ix = Index::open(&st).unwrap();
    (t, st, ix)
}

#[test]
fn error_mid_batch_rolls_back_to_prior_state() {
    let (_t, _st, ix) = fresh();
    ix.upsert(&entry(0)).unwrap();
    let r: Result<(), _> = ix.batch(|ix| {
        for i in 1..50 {
            ix.upsert(&entry(i))?;
        }
        ix.remove(&entry(0).path)?;
        Err(StoreError::NoStore)
    });
    assert!(matches!(r, Err(StoreError::NoStore)), "{r:?}");
    assert_eq!(ix.iter().unwrap(), vec![entry(0)]);
    // After a rollback the connection is usable again (no dangling
    // transaction).
    ix.batch(|ix| ix.upsert(&entry(1))).unwrap();
    assert_eq!(ix.iter().unwrap().len(), 2);
}

// IMMEDIATE, not DEFERRED: the write lock is taken before the closure runs,
// so a second connection's batch waits (busy_timeout) instead of starting,
// then proceeds once the first commits. A deferred BEGIN would run its
// closure at once.
#[test]
fn second_batch_waits_for_the_first() {
    use std::sync::mpsc;
    use std::time::Duration;
    let (_t, st, first) = fresh();
    let second = Index::open(&st).unwrap();
    let (started, started_rx) = mpsc::channel();
    let (done, done_rx) = mpsc::channel();
    first
        .batch(|ix| {
            ix.upsert(&entry(1))?;
            std::thread::spawn(move || {
                let r = second.batch(|ix| {
                    started.send(()).unwrap();
                    ix.upsert(&entry(2))
                });
                done.send(r.is_ok()).unwrap();
            });
            assert!(
                started_rx.recv_timeout(Duration::from_millis(400)).is_err(),
                "second batch ran while the first held the write lock"
            );
            Ok(())
        })
        .unwrap();
    assert!(done_rx.recv_timeout(Duration::from_secs(10)).unwrap());
    assert_eq!(first.iter().unwrap().len(), 2);
}
