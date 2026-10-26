//! Descriptor hashing with a before/after stability check.

use crate::digest::{Alg, Digest};
use crate::index::Meta;
use std::fs::File;

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
    _file: &File,
    _alg: Alg,
    _after_chunk: &mut dyn FnMut(u64),
) -> Result<(Digest, Meta), HashError> {
    todo!("step 3")
}
