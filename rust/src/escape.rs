//! TSV field escaping (https://github.com/Cyphrme/TSV), shared by command
//! output, the registry and the export files.
//!
//! Only backslash, tab and newline are escaped; every other byte, including
//! control characters and invalid UTF-8, is verbatim. A terminal user who
//! wants raw bytes asks for `-0`.

/// Injective: `\` is doubled, so a literal `\t` in a path cannot collide with
/// an escaped tab.
pub fn escape(path: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len());
    for &b in path {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\n' => out.extend_from_slice(b"\\n"),
            _ => out.push(b),
        }
    }
    out
}

/// Escaped text for messages: lossy where the path is not UTF-8.
pub fn display(path: &[u8]) -> String {
    String::from_utf8_lossy(&escape(path)).into_owned()
}

/// One left-to-right pass over backslash pairs. Replacing `\\` first and
/// `\t` second across the whole field would turn `\\t` into a tab.
pub fn unescape(s: &[u8]) -> Result<Vec<u8>, EscapeError> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' {
            out.push(s[i]);
            i += 1;
            continue;
        }
        match s.get(i + 1) {
            None => return Err(EscapeError::Truncated),
            Some(b'\\') => out.push(b'\\'),
            Some(b't') => out.push(b'\t'),
            Some(b'n') => out.push(b'\n'),
            Some(_) => return Err(EscapeError::BadEscape { index: i }),
        }
        i += 2;
    }
    Ok(out)
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EscapeError {
    #[error("bad escape at index {index}")]
    /// `index` is a byte offset into the input.
    BadEscape { index: usize },
    #[error("truncated escape")]
    Truncated,
}
