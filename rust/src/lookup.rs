//! The lookup loop over backends (ES-1 to ES-7, ES-11): no I/O of its own.
//!
//! Contract skeleton: signatures only.

use crate::cache::{TmpFile, Verified};
use crate::digest::Alg;
use crate::services::Fetchable;
use std::io::{self, Read, Write};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_size: u64,
    pub idle: Duration,
    pub total: Duration,
}

/// What a backend returns. `Hit` carries the candidate's bytes in the sink it
/// was given; the loop, not the backend, decides Verified or Mismatch.
pub enum Fetched {
    Hit(TmpFile),
    Missing,
    Error(String),
}

pub trait Backend {
    /// ES-4: whether this backend can address `alg`.
    fn addresses(&self, alg: Alg) -> bool;
    fn fetch(&self, d: &Fetchable, limits: &Limits, sink: TmpFile) -> Fetched;
}

/// The per-service outcome (ES-5, ES-6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Hit,
    Missing,
    Error(String),
    Mismatch,
    Skipped,
}

#[derive(Debug)]
pub struct Attempt {
    pub service: String,
    pub outcome: Outcome,
}

pub struct Found {
    pub attempts: Vec<Attempt>,
    /// Set when some service delivered a candidate that verified.
    pub hit: Option<Verified>,
}

/// Tries `services` one at a time in order (ES-3); `tmp` supplies one sink per
/// attempted fetch.
pub fn run(
    services: &[(String, &dyn Backend)],
    d: &Fetchable,
    limits: &Limits,
    tmp: &mut dyn FnMut() -> io::Result<TmpFile>,
) -> io::Result<Found> {
    let _ = (services, d, limits, tmp);
    todo!("ES-3 loop")
}

/// ES-7. `write_failed`: a private copy or cache admission that was needed
/// could not be written. `index_failed`: an index record failed verification
/// under `cat`.
pub fn exit_code(outcomes: &[Outcome], index_failed: bool, write_failed: bool) -> u8 {
    let _ = (outcomes, index_failed, write_failed);
    todo!("ES-7")
}

#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error("content does not hash to the requested digest")]
    Mismatch,
    #[error("{0}")]
    Io(#[from] io::Error),
}

/// ES-11: copies `src` once into `tmp`, hashes the whole copy, and only then
/// writes the copy to `sink`. Returns the verified copy's size.
pub fn emit_verified(
    src: &mut dyn Read,
    tmp: TmpFile,
    d: &Fetchable,
    sink: &mut dyn Write,
) -> Result<u64, EmitError> {
    let _ = (src, tmp, d, sink);
    todo!("ES-11")
}
