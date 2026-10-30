//! The lookup loop over backends (ES-1 to ES-7, ES-11): no I/O of its own.

use crate::cache::{TmpFile, Verified, VerifyError};
use crate::digest::Alg;
use crate::services::Fetchable;
use std::io::{self, Read, Seek, SeekFrom, Write};
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
/// attempted fetch. A sink that cannot be made ends the walk with the error:
/// the blob may exist, so going on to report a miss would be wrong (ES-25).
pub fn run(
    services: &[(String, &dyn Backend)],
    d: &Fetchable,
    limits: &Limits,
    tmp: &mut dyn FnMut() -> io::Result<TmpFile>,
) -> io::Result<Found> {
    let mut attempts = Vec::new();
    for (name, backend) in services {
        let mut record = |outcome| {
            attempts.push(Attempt {
                service: name.clone(),
                outcome,
            })
        };
        if !backend.addresses(d.digest().alg()) {
            record(Outcome::Skipped);
            continue;
        }
        match backend.fetch(d, limits, tmp()?) {
            Fetched::Missing => record(Outcome::Missing),
            Fetched::Error(e) => record(Outcome::Error(e)),
            Fetched::Hit(candidate) => match Verified::check(candidate, d) {
                Ok(v) => {
                    record(Outcome::Hit);
                    return Ok(Found {
                        attempts,
                        hit: Some(v),
                    });
                }
                // The candidate's bytes go with it: dropping the sink deletes them.
                Err(VerifyError::Mismatch) => record(Outcome::Mismatch),
                Err(e @ VerifyError::Io(_)) => record(Outcome::Error(e.to_string())),
            },
        }
    }
    Ok(Found {
        attempts,
        hit: None,
    })
}

/// ES-7. `write_failed`: a private copy or cache admission that was needed
/// could not be written. `index_failed`: an index record failed verification
/// under `cat`.
pub fn exit_code(outcomes: &[Outcome], index_failed: bool, write_failed: bool) -> u8 {
    let hit = outcomes.contains(&Outcome::Hit);
    let failed = outcomes
        .iter()
        .any(|o| matches!(o, Outcome::Error(_) | Outcome::Mismatch));
    if hit && !write_failed {
        0
    } else if index_failed {
        2
    } else if failed || write_failed {
        5
    } else {
        1
    }
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
    let mut tmp = tmp;
    io::copy(src, tmp.file())?;
    let v = Verified::check(tmp, d).map_err(|e| match e {
        VerifyError::Mismatch => EmitError::Mismatch,
        VerifyError::Io(e) => EmitError::Io(e),
    })?;
    let mut copy = v.reopen()?;
    copy.seek(SeekFrom::Start(0))?;
    let n = io::copy(&mut copy, sink)?;
    if n != v.size() {
        return Err(EmitError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the private copy changed after it was verified",
        )));
    }
    Ok(n)
}
