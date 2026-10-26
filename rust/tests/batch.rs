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
