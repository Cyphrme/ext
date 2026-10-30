//! External services: the services file (ES-21, ES-22), service URIs and the
//! request each one receives (ES-23).
//!
//! Contract skeleton: signatures only. Bodies are filled by the implementation.

use crate::cache::StepExecutor;
use crate::digest::Digest;
use crate::store::{Store, WriteLock};

/// At most this many services are registered (ES-3).
pub const MAX_SERVICES: usize = 64;

/// A digest a service may be asked for (ES-2): full length for its algorithm,
/// and the algorithm is cryptographic and supported. `Digest` already carries
/// the first property, so this wrapper is the type a backend accepts and the
/// one place the rule is stated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetchable(Digest);

impl Fetchable {
    pub fn new(d: Digest) -> Fetchable {
        Fetchable(d)
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Https,
    Http,
}

/// A line of the services file in normal form (scheme and host lowercased).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceUri {
    normal: String,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct UriError(pub String);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    /// `line` is 1-based.
    #[error("services file: line {line}: {source}")]
    Line { line: usize, source: UriError },
    #[error("services file: more than {MAX_SERVICES} services")]
    TooMany,
}

impl ServiceUri {
    /// One line without its LF, per the ES-21 grammar.
    pub fn parse(line: &str) -> Result<ServiceUri, UriError> {
        let _ = line;
        todo!("ES-21 grammar")
    }

    /// The normal form, which is what the services file stores.
    pub fn as_str(&self) -> &str {
        &self.normal
    }

    pub fn scheme(&self) -> Scheme {
        todo!("ES-21")
    }

    /// The URL requested for `d` (ES-23).
    pub fn request_url(&self, d: &Fetchable) -> String {
        let _ = d;
        todo!("ES-23")
    }
}

/// Parses the whole file: LF-terminated records, no blank lines, comments or
/// duplicates (after normalisation), at most [`MAX_SERVICES`].
pub fn parse_file(bytes: &[u8]) -> Result<Vec<ServiceUri>, FileError> {
    let _ = bytes;
    todo!("ES-21")
}

pub fn render_file(services: &[ServiceUri]) -> Vec<u8> {
    let _ = services;
    todo!("ES-21")
}

/// Atomic replace of `<store>/services` through the executor (ES-22, F10).
pub fn write_file(
    store: &Store,
    lock: &WriteLock,
    ex: &mut dyn StepExecutor,
    services: &[ServiceUri],
) -> std::io::Result<()> {
    let _ = (store, lock, ex, services);
    todo!("ES-22 atomic write")
}
