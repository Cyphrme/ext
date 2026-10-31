//! Descriptor hashing with a before/after stability check.

use crate::digest::{Alg, Digest};
use crate::index::Meta;
use sha2::{Digest as _, Sha256};
use std::fs::{File, Metadata};
use std::io::ErrorKind;
use std::os::unix::fs::{FileExt, MetadataExt};

const CHUNK: usize = 128 << 10;

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("file changed while it was being hashed")]
    Unstable,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// `after_chunk` receives the cumulative bytes hashed so far; production
/// passes a no-op. The caller owns the single retry.
pub fn hash_stable(
    file: &File,
    alg: Alg,
    after_chunk: &mut dyn FnMut(u64),
) -> Result<(Digest, Meta), HashError> {
    let before = meta_of(&file.metadata()?);
    let mut hasher = match alg {
        Alg::Sha256 => Sha256::new(),
    };
    // Positioned reads: a retry on the same descriptor starts at 0 without
    // depending on, or disturbing, the shared file offset.
    let mut buf = vec![0u8; CHUNK];
    let mut off: u64 = 0;
    // Bounded by the size seen up front: a file that keeps growing cannot
    // keep the hash running; the size comparison below reports it instead.
    while off < before.size {
        let want = usize::try_from(before.size - off).map_or(CHUNK, |r| r.min(CHUNK));
        let n = match file.read_at(&mut buf[..want], off) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        hasher.update(&buf[..n]);
        off += n as u64;
        after_chunk(off);
    }
    let after = meta_of(&file.metadata()?);
    // A short read means the file shrank after the first fstat; the
    // metadata comparison normally catches that too, so this is plain
    // defence against a read that ends early for any other reason.
    if before != after || off != before.size {
        return Err(HashError::Unstable);
    }
    let digest = Digest::from_bytes(alg, &hasher.finalize())
        .map_err(|e| std::io::Error::other(format!("digest length: {e}")))?;
    Ok((digest, after))
}

pub(crate) fn meta_of(md: &Metadata) -> Meta {
    Meta {
        size: md.size(),
        mtime_ns: ts_ns(md.mtime(), md.mtime_nsec()),
        ctime_ns: ts_ns(md.ctime(), md.ctime_nsec()),
        dev: md.dev(),
        ino: md.ino(),
    }
}

/// Saturating so a hostile timestamp far outside i64 nanoseconds cannot
/// overflow-panic; saturation lands in the racy range, which only costs a
/// re-hash.
fn ts_ns(sec: i64, nsec: i64) -> i64 {
    sec.saturating_mul(1_000_000_000).saturating_add(nsec)
}
