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

/// One store+index for all cases: creating a store per case made this test
/// take ~10 s.
#[test]
fn arbitrary_path_bytes_roundtrip() {
    let (_t, _st, ix) = fresh();
    proptest!(ProptestConfig::with_cases(64), |(tail in prop::collection::vec(any::<u8>(), 0..40))| {
        let mut p = vec![b'/'];
        p.extend(tail);
        let e = entry(&p, b"x");
        ix.upsert(&e).unwrap();
        prop_assert_eq!(ix.get(&p).unwrap(), Some(e));
    });
}

/// i64/u64 boundary values for every numeric column.
#[test]
fn meta_extremes_roundtrip() {
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
    for v in [i64::MAX as u64 + 1, u64::MAX, u64::MAX - 1] {
        let mut e = entry(b"/big", b"b");
        e.meta.size = v;
        e.meta.dev = v;
        e.meta.ino = v;
        ix.upsert(&e).unwrap();
        assert_eq!(ix.get(b"/big").unwrap(), Some(e), "{v}");
    }
}

/// R6: every path with the digest, ordered by raw bytes (memcmp) rather than
/// text collation; a replaced entry leaves its old digest; a miss is empty.
#[test]
fn by_digest() {
    let (_t, _st, ix) = fresh();
    let paths: [&[u8]; 6] = [b"/b", b"/\xff", b"/a", b"/\x7f", b"/a/b", b"/A"];
    for p in paths {
        ix.upsert(&entry(p, b"same")).unwrap();
    }
    ix.upsert(&entry(b"/different", b"other content")).unwrap();
    let same = Digest::compute(Alg::Sha256, b"same");
    let mut want: Vec<Vec<u8>> = paths.iter().map(|p| p.to_vec()).collect();
    want.sort();
    assert_eq!(ix.by_digest(&same).unwrap(), want);
    assert!(ix
        .by_digest(&Digest::compute(Alg::Sha256, b"absent"))
        .unwrap()
        .is_empty());

    ix.upsert(&entry(b"/f", b"v1")).unwrap();
    ix.upsert(&entry(b"/f", b"v2")).unwrap();
    let v1 = Digest::compute(Alg::Sha256, b"v1");
    let v2 = Digest::compute(Alg::Sha256, b"v2");
    assert!(ix.by_digest(&v1).unwrap().is_empty());
    assert_eq!(ix.by_digest(&v2).unwrap(), vec![b"/f".to_vec()]);
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
fn schema_version_mismatch_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    drop(Index::open(&st).unwrap());
    let raw = Connection::open(dir.join("index.db")).unwrap();
    let v: i64 = raw
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 1);
    raw.pragma_update(None, "user_version", 2).unwrap();
    assert!(
        Index::open(&st).is_err(),
        "user_version 2 must be refused, no migrations"
    );
}

/// R4 boundary: "under root" means equal or prefixed by `root/`, never a bare
/// byte prefix, including when one root is a byte-prefix of another. "/" keeps
/// everything and an empty registry drops everything.
#[test]
fn reconcile() {
    let (_t, _st, ix) = fresh();
    // (entries, roots, entries kept)
    type Row<'a> = (&'a [&'a [u8]], &'a [&'a [u8]], &'a [&'a [u8]]);
    let rows: &[Row] = &[
        (
            &[b"/r1/a", b"/r1x/a", b"/r1", b"/a/x", b"/ab/y", b"/abc/z"],
            &[b"/r1"],
            &[b"/r1", b"/r1/a"],
        ),
        (
            &[b"/a/x", b"/ab/y", b"/abc/z"],
            &[b"/a", b"/ab"],
            &[b"/a/x", b"/ab/y"],
        ),
        (&[b"/a/x", b"/ab/y", b"/abc/z"], &[b"/ab"], &[b"/ab/y"]),
        (&[b"/a", b"/b/c"], &[b"/"], &[b"/a", b"/b/c"]),
        (&[b"/a", b"/b/c"], &[], &[]),
    ];
    for (entries, roots, want) in rows {
        ix.reconcile(&[]).unwrap();
        for p in *entries {
            ix.upsert(&entry(p, p)).unwrap();
        }
        let roots: Vec<_> = roots.iter().map(|r| rp(r)).collect();
        ix.reconcile(&roots).unwrap();
        let mut left: Vec<_> = ix.iter().unwrap().into_iter().map(|e| e.path).collect();
        left.sort();
        let want: Vec<Vec<u8>> = want.iter().map(|p| p.to_vec()).collect();
        assert_eq!(left, want, "roots {roots:?}");
    }
}

/// A damaged or hostile index.db must be inert: a trigger planted by an
/// independent connection fires on the next upsert and tries to rewrite an
/// FTS shadow table, which SQLITE_DBCONFIG_DEFENSIVE forbids. (The
/// `trusted_schema=OFF` line is not separately testable: the bundled SQLite
/// already defaults it off, so no behaviour distinguishes the two.)
#[test]
fn hostile_database_cannot_rewrite_shadow_tables() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("s");
    let st = Store::init_bare(&dir).unwrap();
    drop(Index::open(&st).unwrap());
    Connection::open(dir.join("index.db"))
        .unwrap()
        .execute_batch(
            "CREATE VIRTUAL TABLE ft USING fts3(x);
             CREATE TRIGGER evil AFTER INSERT ON files
             BEGIN INSERT INTO ft_content(docid, c0x) VALUES (1, 'evil'); END;",
        )
        .unwrap();
    let ix = Index::open(&st).unwrap();
    let err = ix.upsert(&entry(b"/x", b"x")).unwrap_err().to_string();
    assert!(err.contains("may not be modified"), "{err}");
}
