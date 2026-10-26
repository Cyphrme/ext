//! Registry file: one escaped absolute path per line.

use crate::escape::EscapeError;

/// A normalised absolute path (no `.`/`..` segments, no `//`, no trailing `/`
/// except for `/` itself).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegPath(Vec<u8>);

#[derive(Debug, PartialEq, Eq)]
pub enum RegistryErrorKind {
    Relative,
    NotNormalised,
    Nul,
    Escape(EscapeError),
}

impl RegPath {
    pub fn from_bytes(_path: &[u8]) -> Result<RegPath, RegistryErrorKind> {
        todo!("step 2: validate and normalise")
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub fn parse(_bytes: &[u8]) -> Result<Vec<RegPath>, (usize, RegistryErrorKind)> {
    todo!("step 2: parse registry")
}

pub fn render(_paths: &[RegPath]) -> Vec<u8> {
    todo!("step 2: render registry")
}
