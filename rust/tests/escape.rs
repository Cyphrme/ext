//! Path escaping is TSV's: `\`, tab and newline are the only escaped bytes,
//! and unescaping is one left-to-right pass over backslash pairs.
//! Reference: https://github.com/Cyphrme/TSV (`tsv.go`).

use ext::escape::{escape, unescape, EscapeError};
use proptest::prelude::*;

fn any_input() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..64)
}

proptest! {
    #[test]
    fn roundtrip(x in any_input()) {
        prop_assert_eq!(unescape(&escape(&x)), Ok(x));
    }

    /// Output holds no tab or newline, and every backslash starts a pair.
    #[test]
    fn output_has_no_delimiters(x in any_input()) {
        let e = escape(&x);
        prop_assert!(!e.contains(&b'\t') && !e.contains(&b'\n'));
        let mut i = 0;
        while i < e.len() {
            if e[i] == b'\\' {
                prop_assert!(matches!(e.get(i + 1), Some(b'\\' | b't' | b'n')));
                i += 1;
            }
            i += 1;
        }
    }

    /// Escaping is injective, so equal wire text means equal bytes.
    #[test]
    fn injective(a in any_input(), b in any_input()) {
        prop_assume!(a != b);
        prop_assert_ne!(escape(&a), escape(&b));
    }

    /// Bytes other than `\`, tab and newline pass through unchanged.
    #[test]
    fn untouched_bytes_are_verbatim(x in any_input()) {
        let x: Vec<u8> = x.into_iter().filter(|b| !matches!(b, b'\\' | b'\t' | b'\n')).collect();
        prop_assert_eq!(escape(&x), x);
    }
}

#[test]
fn escape_examples() {
    let rows: &[(&[u8], &[u8])] = &[
        (b"a\\b", b"a\\\\b"),
        (b"\t", b"\\t"),
        (b"\n", b"\\n"),
        (b"\\t", b"\\\\t"),
        (b"a\tb\nc", b"a\\tb\\nc"),
        // Everything else is verbatim: controls, invalid UTF-8, bidi, CR.
        (b"\x1B", b"\x1B"),
        (b"\r", b"\r"),
        (b"\x7F", b"\x7F"),
        (b"\xFF\xC3", b"\xFF\xC3"),
        ("\u{80}".as_bytes(), "\u{80}".as_bytes()),
        ("\u{202E}".as_bytes(), "\u{202E}".as_bytes()),
        ("é日本語🙂".as_bytes(), "é日本語🙂".as_bytes()),
    ];
    for (raw, wire) in rows {
        assert_eq!(escape(raw), *wire, "{raw:?}");
        assert_eq!(unescape(wire), Ok(raw.to_vec()), "{wire:?}");
    }
}

/// One pass: the pair `\\` is consumed before the `t` is looked at, so
/// `\\t` is backslash then `t`, never a tab.
#[test]
fn unescape_is_a_single_pass() {
    assert_eq!(unescape(b"\\\\t"), Ok(b"\\t".to_vec()));
    assert_eq!(unescape(b"\\\\\\t"), Ok(b"\\\t".to_vec()));
    assert_eq!(unescape(b"\\\\n\\n"), Ok(b"\\n\n".to_vec()));
}

#[test]
fn unescape_rejects() {
    let rows: &[(&[u8], Option<usize>)] = &[
        (b"\\q", Some(0)),
        (b"ab\\x41", Some(2)),
        (b"\\r", Some(0)),
        (b"\\0", Some(0)),
        // Case matters: only lowercase t and n.
        (b"\\T", Some(0)),
        (b"\\N", Some(0)),
        (b"\\", None),
        (b"ok\\", None),
        (b"\\\\\\", None),
    ];
    for (s, idx) in rows {
        let r = unescape(s);
        assert!(r.is_err(), "{s:?}");
        match idx {
            Some(index) => assert_eq!(r, Err(EscapeError::BadEscape { index: *index }), "{s:?}"),
            None => assert_eq!(r, Err(EscapeError::Truncated), "{s:?}"),
        }
    }
}
