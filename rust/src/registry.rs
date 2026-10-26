//! Registry file: one escaped absolute path per line.

use crate::escape::{escape, unescape, EscapeError};
use std::collections::HashSet;

/// A normalised absolute path (no `.`/`..` segments, no `//`, no trailing `/`
/// except for `/` itself).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegPath(Vec<u8>);

#[derive(Debug, PartialEq, Eq)]
pub enum RegistryErrorKind {
    Relative,
    NotNormalised,
    Nul,
    NotUtf8,
    Escape(EscapeError),
}

impl RegPath {
    /// Collapses `//` and a trailing `/` (lexical-only, always safe) but
    /// rejects `.`/`..`: resolving `..` lexically changes meaning when a
    /// symlink precedes it.
    pub fn from_bytes(path: &[u8]) -> Result<RegPath, RegistryErrorKind> {
        if path.first() != Some(&b'/') {
            return Err(RegistryErrorKind::Relative);
        }
        if path.contains(&0) {
            return Err(RegistryErrorKind::Nul);
        }
        let mut out = Vec::with_capacity(path.len());
        for seg in path.split(|&b| b == b'/').filter(|s| !s.is_empty()) {
            if seg == b"." || seg == b".." {
                return Err(RegistryErrorKind::NotNormalised);
            }
            out.push(b'/');
            out.extend_from_slice(seg);
        }
        if out.is_empty() {
            out.push(b'/');
        }
        Ok(RegPath(out))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Blank lines and `#` lines are skipped (`#` cannot begin an absolute path,
/// so this is unambiguous). Duplicates after normalisation keep their first
/// position. Errors carry the 1-based line number.
pub fn parse(bytes: &[u8]) -> Result<Vec<RegPath>, (usize, RegistryErrorKind)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (i, line) in bytes.split(|&b| b == b'\n').enumerate() {
        let lineno = i + 1;
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let text = std::str::from_utf8(line).map_err(|_| (lineno, RegistryErrorKind::NotUtf8))?;
        let raw = unescape(text).map_err(|e| (lineno, RegistryErrorKind::Escape(e)))?;
        let p = RegPath::from_bytes(&raw).map_err(|k| (lineno, k))?;
        if seen.insert(p.clone()) {
            out.push(p);
        }
    }
    Ok(out)
}

pub fn render(paths: &[RegPath]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in paths {
        out.extend_from_slice(escape(p.as_bytes()).as_bytes());
        out.push(b'\n');
    }
    out
}
