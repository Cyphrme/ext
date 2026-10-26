//! Acceptance tests for plan §3 `index.rs` (schema A3, path round-trip,
//! digest lookup, registry-authoritative reconcile).

mod common;
use common::rp;
use ext::digest::{Alg, Digest};
use ext::index::{Entry, Index, Meta};
use ext::store::Store;
use proptest::prelude::*;
use rusqlite::Connection;

fn entry(path: &[u8], content: &[u8]) -> Entry {
    Entry {
        path: path.to_vec(),
        digest: Digest::compute(Alg::Sha256, content),
        meta: Meta {
            size: content.len() as u64,
            mtime_ns: 1_700_000_000_123_456_789,
            ctime_ns: 1_700_000_000_987_654_321,
            dev: 64768,
            ino: 4242,
        },
        last_checked_ns: 1_700_000_005_000_000_000,
    }
}

fn fresh() -> (tempfile::TempDir, Store, Index) {
    let t = tempfile::tempdir().unwrap();
    let st = Store::init_bare(&t.path().join("s")).unwrap();
    let ix = Index::open(&st).unwrap();
    (t, st, ix)
}

fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    v.sort();
    v
}

#[test]
fn awkward_path_bytes_roundtrip() {
    let (_t, _st, ix) = fresh();
    for p in [
        &b"/a\tb"[..],
        b"/a\nb",
        b"/a\\b",
        b"/\xff\xfe",
        b"/a\\x41",
        "/caf\u{e9}".as_bytes(),
    ] {
        let e = entry(p, p);
        ix.upsert(&e).unwrap();
        assert_eq!(ix.get(p).unwrap(), Some(e), "{p:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn arbitrary_path_bytes_roundtrip(tail in prop::collection::vec(any::<u8>(), 0..40)) {
        let (_t, _st, ix) = fresh();
        let mut p = vec![b'/'];
        p.extend(tail);
        let e = entry(&p, b"x");
        ix.upsert(&e).unwrap();
        prop_assert_eq!(ix.get(&p).unwrap(), Some(e));
    }
}

#[test]
fn get_missing_is_none() {
    let (_t, _st, ix) = fresh();
    assert_eq!(ix.get(b"/nope").unwrap(), None);
}

#[test]
fn meta_fields_roundtrip_exactly() {
    let (_t, _st, ix) = fresh();
    let mut e = entry(b"/m", b"m");
    e.meta = Meta {
        size: i64::MAX as u64,
        mtime_ns: -5,
        ctime_ns: i64::MAX,
        dev: i64::MAX as u64,
        ino: i64::MAX as u64,
    };
    e.last_checked_ns = i64::MAX;
    ix.upsert(&e).unwrap();
    assert_eq!(ix.get(b"/m").unwrap(), Some(e));
}

#[test]
fn by_digest_returns_every_path_with_that_digest() {
    let (_t, _st, ix) = fresh();
    for p in [&b"/r/one"[..], b"/r/two", b"/other/root/three"] {
        ix.upsert(&entry(p, b"same content")).unwrap();
    }
    ix.upsert(&entry(b"/r/different", b"other content"))
        .unwrap();
    let d = Digest::compute(Alg::Sha256, b"same content");
    assert_eq!(
        sorted(ix.by_digest(&d).unwrap()),
        vec![
            b"/other/root/three".to_vec(),
            b"/r/one".to_vec(),
            b"/r/two".to_vec()
        ]
    );
    assert!(ix
        .by_digest(&Digest::compute(Alg::Sha256, b"absent"))
        .unwrap()
        .is_empty());
}

#[test]
fn upsert_replaces_by_path_and_updates_digest_lookup() {
    let (_t, _st, ix) = fresh();
    ix.upsert(&entry(b"/f", b"v1")).unwrap();
    ix.upsert(&entry(b"/f", b"v2")).unwrap();
    assert!(ix
        .by_digest(&Digest::compute(Alg::Sha256, b"v1"))
        .unwrap()
        .is_empty());
    assert_eq!(
        ix.by_digest(&Digest::compute(Alg::Sha256, b"v2")).unwrap(),
        vec![b"/f".to_vec()]
    );
    assert_eq!(ix.iter().unwrap().len(), 1);
}

#[test]
fn remove_and_remove_under_respect_path_boundaries() {
    let (_t, _st, ix) = fresh();
    for p in [&b"/r/a"[..], b"/r/b/c", b"/rx/a", b"/other"] {
        ix.upsert(&entry(p, p)).unwrap();
    }
    ix.remove(b"/other").unwrap();
    assert_eq!(ix.get(b"/other").unwrap(), None);
    assert_eq!(
        sorted(ix.paths_under(&rp(b"/r")).unwrap()),
        vec![b"/r/a".to_vec(), b"/r/b/c".to_vec()]
    );
    ix.remove_under(&rp(b"/r")).unwrap();
    let left: Vec<_> = ix.iter().unwrap().into_iter().map(|e| e.path).collect();
    assert_eq!(
        left,
        vec![b"/rx/a".to_vec()],
        "sibling /rx must survive removal of /r"
    );
}

#[test]
fn iter_yields_all_entries() {
    let (_t, _st, ix) = fresh();
    for i in 0..5 {
        ix.upsert(&entry(format!("/p/{i}").as_bytes(), b"c"))
            .unwrap();
    }
    assert_eq!(ix.iter().unwrap().len(), 5);
}

/// A3: schema columns, the (alg,digest) index, and PRAGMA user_version = 1.
#[test]
fn schema_matches_plan_a3() {
    let (_t, st, ix) = fresh();
    drop(ix);
    drop(st);
    // Re-open the raw database independently of the code under test.
    let t2 = tempfile::tempdir().unwrap();
    let dir = t2.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    drop(Index::open(&st).unwrap());
    let c = Connection::open(dir.join("index.db")).unwrap();
    let v: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 1);
    let mut stmt = c.prepare("PRAGMA table_info(files)").unwrap();
    let mut cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    cols.sort();
    let mut want = [
        "path",
        "alg",
        "digest",
        "size",
        "mtime_ns",
        "ctime_ns",
        "dev",
        "ino",
        "last_checked_ns",
    ]
    .map(String::from)
    .to_vec();
    want.sort();
    assert_eq!(cols, want);
    let idx_cols: Vec<String> = c
        .prepare("PRAGMA index_info(files_digest)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(2))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(idx_cols, ["alg", "digest"]);
}

#[test]
fn schema_version_mismatch_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    drop(Index::open(&st).unwrap());
    Connection::open(dir.join("index.db"))
        .unwrap()
        .pragma_update(None, "user_version", 2)
        .unwrap();
    assert!(
        Index::open(&st).is_err(),
        "user_version 2 must be refused, no migrations"
    );
}

#[test]
fn index_persists_across_reopen() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    let e = entry(b"/persist", b"p");
    Index::open(&st).unwrap().upsert(&e).unwrap();
    let st2 = Store::open(&dir).unwrap();
    assert_eq!(
        Index::open(&st2).unwrap().get(b"/persist").unwrap(),
        Some(e)
    );
}

/// §1 "The registry is authoritative": after a crash between the registry
/// write and the index write (simulated by performing only the registry
/// write), reconciling against the registry converges the index.
#[test]
fn index_converges_to_registry_after_simulated_crash() {
    let (_t, st, ix) = fresh();
    let lock = st.lock().unwrap();
    st.edit_registry(&lock, |v| v.extend([rp(b"/r1"), rp(b"/r2")]))
        .unwrap();
    drop(lock);
    for p in [&b"/r1/a"[..], b"/r1/sub/b", b"/r2/c", b"/r2x/d"] {
        ix.upsert(&entry(p, p)).unwrap();
    }
    // unregister /r2: registry write lands, the index write never happens.
    let lock = st.lock().unwrap();
    st.edit_registry(&lock, |v| v.retain(|r| r.as_bytes() != b"/r2"))
        .unwrap();
    drop(lock);
    assert!(
        ix.get(b"/r2/c").unwrap().is_some(),
        "precondition: index is stale"
    );

    ix.reconcile(&st.registry().unwrap()).unwrap();
    let mut left: Vec<_> = ix.iter().unwrap().into_iter().map(|e| e.path).collect();
    left.sort();
    assert_eq!(left, vec![b"/r1/a".to_vec(), b"/r1/sub/b".to_vec()]);
    // Idempotent.
    ix.reconcile(&st.registry().unwrap()).unwrap();
    assert_eq!(ix.iter().unwrap().len(), 2);
}

#[test]
fn reconcile_with_root_slash_keeps_everything_and_empty_registry_drops_all() {
    let (_t, _st, ix) = fresh();
    ix.upsert(&entry(b"/a", b"a")).unwrap();
    ix.upsert(&entry(b"/b/c", b"c")).unwrap();
    ix.reconcile(&[rp(b"/")]).unwrap();
    assert_eq!(ix.iter().unwrap().len(), 2);
    ix.reconcile(&[]).unwrap();
    assert!(ix.iter().unwrap().is_empty());
}
