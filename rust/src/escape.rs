//! Path escaping shared by command output and the registry.

/// Exactly Unicode's Bidi_Control property (12 code points).
fn is_bidi_control(u: u32) -> bool {
    matches!(u, 0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069)
}

fn push_hex(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push_str("\\x");
    out.push(HEX[usize::from(b >> 4)] as char);
    out.push(HEX[usize::from(b & 15)] as char);
}

/// Injective: `\` is doubled, so a literal `\x1B` in a path cannot collide
/// with an escaped ESC byte. Output holds no C0, DEL, C1 or bidi-control
/// code points.
pub fn escape(path: &[u8]) -> String {
    let mut out = String::with_capacity(path.len());
    for chunk in path.utf8_chunks() {
        for c in chunk.valid().chars() {
            let u = c as u32;
            if c == '\\' {
                out.push_str("\\\\");
            } else if u < 0x20 || u == 0x7F {
                push_hex(&mut out, u as u8);
            } else if (0x80..=0x9F).contains(&u) || is_bidi_control(u) {
                // Valid UTF-8, but C1 controls act on terminals and bidi
                // controls let a filename reorder the text around it.
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

/// Accepts only the escape forms `escape` emits (`\\` and uppercase `\xNN`);
/// all other text passes through as-is, so `\x41` and `A` both decode to
/// 0x41. Decoding is therefore not injective on escaped text.
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
    /// `index` is a byte offset into the input.
    BadEscape { index: usize },
    #[error("truncated escape")]
    Truncated,
}
