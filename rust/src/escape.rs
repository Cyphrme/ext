//! Path escaping shared by command output and the registry.

pub fn escape(_path: &[u8]) -> String {
    todo!()
}

pub fn unescape(_s: &str) -> Result<Vec<u8>, EscapeError> {
    todo!()
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EscapeError {
    #[error("bad escape at index {index}")]
    BadEscape { index: usize },
    #[error("truncated escape")]
    Truncated,
}
