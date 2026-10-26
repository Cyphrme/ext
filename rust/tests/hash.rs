//! Plan §4 `hash.rs` (A8, T4): hashing a descriptor detects a file that
//! changes underneath it.

mod support;
use ext::digest::{Alg, Digest};
use ext::hash::{hash_stable, HashError};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::thread::sleep;
use std::time::Duration;

const SIZE: usize = 2 << 20;

fn big(dir: &std::path::Path) -> (std::path::PathBuf, Vec<u8>) {
    let p = dir.join("big");
    let data: Vec<u8> = (0..SIZE).map(|i| (i * 31 % 251) as u8).collect();
    fs::write(&p, &data).unwrap();
    (p, data)
}

#[test]
fn stable_file_digest_and_meta_match() {
    let (_t, d) = support::canon_tmp();
    let (p, data) = big(&d);
    let f = File::open(&p).unwrap();
    let mut calls = Vec::new();
    let (dg, meta) = hash_stable(&f, Alg::Sha256, &mut |n| calls.push(n)).unwrap();
    assert_eq!(dg, Digest::compute(Alg::Sha256, &data));
    assert_eq!(meta.size, SIZE as u64);
    let md = fs::metadata(&p).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!((meta.ino, meta.dev), (md.ino(), md.dev()));
    assert_eq!(meta.mtime_ns, md.mtime() * 1_000_000_000 + md.mtime_nsec());
    assert_eq!(meta.ctime_ns, md.ctime() * 1_000_000_000 + md.ctime_nsec());
    // The seam must actually fire, or the mid-hash tests below prove nothing.
    assert!(!calls.is_empty(), "after_chunk never called");
    assert!(
        calls.windows(2).all(|w| w[0] <= w[1]),
        "not cumulative: {calls:?}"
    );
    assert_eq!(*calls.last().unwrap(), SIZE as u64);

    // The empty file is the loop-skip edge.
    let e = d.join("e");
    fs::write(&e, b"").unwrap();
    let (dg, m) = hash_stable(&File::open(&e).unwrap(), Alg::Sha256, &mut |_| {}).unwrap();
    assert_eq!(dg, Digest::compute(Alg::Sha256, b""));
    assert_eq!(m.size, 0);
}

// T4, size-changing variant.
#[test]
fn append_mid_hash_is_unstable() {
    let (_t, d) = support::canon_tmp();
    let (p, _) = big(&d);
    let f = File::open(&p).unwrap();
    let mut done = false;
    let r = hash_stable(&f, Alg::Sha256, &mut |_| {
        if !done {
            done = true;
            OpenOptions::new()
                .append(true)
                .open(&p)
                .unwrap()
                .write_all(b"x")
                .unwrap();
        }
    });
    assert!(matches!(r, Err(HashError::Unstable)), "{r:?}");
}

// T4, same-size variant: only mtime/ctime can reveal it. The sleep keeps the
// edit out of the creation tick of the kernel's coarse clock, so a detector
// that ignored ctime/mtime could not pass by luck.
#[test]
fn same_size_rewrite_mid_hash_is_unstable() {
    let (_t, d) = support::canon_tmp();
    let (p, _) = big(&d);
    let f = File::open(&p).unwrap();
    let mut done = false;
    let r = hash_stable(&f, Alg::Sha256, &mut |_| {
        if !done {
            done = true;
            sleep(Duration::from_millis(50));
            let before = fs::metadata(&p).unwrap();
            let mut w = OpenOptions::new().write(true).open(&p).unwrap();
            w.write_all(b"ZZZZ").unwrap();
            // Premises: size unchanged, so only a timestamp can reveal this,
            // and the clock actually moved (else the test is not testing).
            let after = fs::metadata(&p).unwrap();
            assert_eq!(before.len(), after.len());
            use std::os::unix::fs::MetadataExt;
            assert_ne!(
                (before.ctime(), before.ctime_nsec()),
                (after.ctime(), after.ctime_nsec())
            );
        }
    });
    assert!(matches!(r, Err(HashError::Unstable)), "{r:?}");
}
