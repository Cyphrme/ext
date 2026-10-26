//! Path escaping shared by command output and the registry.

fn push_hex(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push_str("\\x");
    out.push(HEX[usize::from(b >> 4)] as char);
    out.push(HEX[usize::from(b & 15)] as char);
}

/// Injective: `\` is doubled, so a literal `\x1B` in a path cannot collide
/// with an escaped ESC byte. Output holds no C0, DEL or C1 code points.
pub fn escape(path: &[u8]) -> String {
    let mut out = String::with_capacity(path.len());
    for chunk in path.utf8_chunks() {
        for c in chunk.valid().chars() {
            let u = c as u32;
            if c == '\\' {
                out.push_str("\\\\");
            } else if u < 0x20 || u == 0x7F {
                push_hex(&mut out, u as u8);
            } else if (0x80..=0x9F).contains(&u) {
                // C1 controls are valid UTF-8 but unsafe on terminals.
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    push_hex(&mut out, b);
                }
            } else {
                out.push(c);
            }
        }
        for &b in chunk.invalid() {
            push_hex(&mut out, b);
        }
    }
    out
}

fn hex_upper(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Accepts only the forms `escape` emits (`\\` and uppercase `\xNN`), so
/// each path has exactly one spelling.
pub fn unescape(s: &str) -> Result<Vec<u8>, EscapeError> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        match b.get(i + 1) {
            None => return Err(EscapeError::Truncated),
            Some(b'\\') => {
                out.push(b'\\');
                i += 2;
            }
            Some(b'x') => {
                let (Some(&h), Some(&l)) = (b.get(i + 2), b.get(i + 3)) else {
                    return Err(EscapeError::Truncated);
                };
                match (hex_upper(h), hex_upper(l)) {
                    (Some(h), Some(l)) => out.push((h << 4) | l),
                    _ => return Err(EscapeError::BadEscape { index: i }),
                }
                i += 4;
            }
            Some(_) => return Err(EscapeError::BadEscape { index: i }),
        }
    }
    Ok(out)
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EscapeError {
    #[error("bad escape at index {index}")]
    BadEscape { index: usize },
    #[error("truncated escape")]
    Truncated,
}
