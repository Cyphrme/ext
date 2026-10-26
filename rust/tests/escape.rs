//! Acceptance tests for plan step 1, section 2.2 (path escaping).

use ext::escape::{escape, unescape, EscapeError};
use proptest::prelude::*;

fn is_forbidden(c: char) -> bool {
    let u = c as u32;
    u < 0x20
        || u == 0x7F
        || (0x80..=0x9F).contains(&u)
        // Unicode Bidi_Control: all 12 code points
        || matches!(u, 0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069)
}

// Bytes alone never reach valid C1/bidi UTF-8; strings alone never reach
// invalid UTF-8. Draw from both.
fn any_input() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..64),
        any::<String>().prop_map(String::into_bytes),
    ]
}

proptest! {
    #[test]
    fn roundtrip(x in any_input()) {
        prop_assert_eq!(unescape(&escape(&x)), Ok(x));
    }

    #[test]
    fn output_is_clean(x in any_input()) {
        prop_assert!(!escape(&x).chars().any(is_forbidden));
    }
}

/// The wire form is the registry's on-disk spelling, so it is pinned
/// exactly, in both directions.
#[test]
fn escape_examples() {
    let rows: &[(&[u8], &str)] = &[
        (b"a\\b", "a\\\\b"),
        (b"\x1B", "\\x1B"),
        (b"\t", "\\x09"),
        (b"\n", "\\x0A"),
        (b"\x00", "\\x00"),
        (b"\x7F", "\\x7F"),
        (b"\x1B\xFF", "\\x1B\\xFF"),
        (b"\xFF", "\\xFF"),
        (b"a\xC3", "a\\xC3"),
        (b"\xE2\x82", "\\xE2\\x82"),
        // C1 controls: every UTF-8 byte is escaped; U+00A0 is just outside
        ("\u{80}".as_bytes(), "\\xC2\\x80"),
        ("\u{85}".as_bytes(), "\\xC2\\x85"),
        ("\u{9F}".as_bytes(), "\\xC2\\x9F"),
        ("\u{A0}".as_bytes(), "\u{A0}"),
        ("é日本語🙂".as_bytes(), "é日本語🙂"),
        (b"plain /path/to file", "plain /path/to file"),
    ];
    for (raw, wire) in rows {
        assert_eq!(escape(raw), *wire, "{raw:?}");
        assert_eq!(unescape(wire), Ok(raw.to_vec()), "{wire:?}");
    }
}

#[test]
fn unescape_rejects() {
    // (input, index when it must be BadEscape at that index)
    let rows: &[(&str, Option<usize>)] = &[
        ("\\q", Some(0)),
        ("\\xZZ", None),
        ("\\x1", None),
        ("\\x", None),
        ("\\", None),
        ("ok\\", None),
        // escapes are uppercase-only
        ("\\x1b", Some(0)),
        ("\\xaB", Some(0)),
    ];
    for (s, idx) in rows {
        let r = unescape(s);
        assert!(r.is_err(), "{s:?}");
        if let Some(index) = idx {
            assert!(matches!(r, Err(EscapeError::BadEscape { index: i }) if i == *index), "{s:?}: {r:?}");
        }
    }
}

#[test]
fn bidi_controls_are_escaped_and_roundtrip() {
    let cases = [
        ('\u{061C}', "\\xD8\\x9C"),
        ('\u{200E}', "\\xE2\\x80\\x8E"),
        ('\u{200F}', "\\xE2\\x80\\x8F"),
        ('\u{202A}', "\\xE2\\x80\\xAA"),
        ('\u{202B}', "\\xE2\\x80\\xAB"),
        ('\u{202C}', "\\xE2\\x80\\xAC"),
        ('\u{202D}', "\\xE2\\x80\\xAD"),
        ('\u{202E}', "\\xE2\\x80\\xAE"),
        ('\u{2066}', "\\xE2\\x81\\xA6"),
        ('\u{2067}', "\\xE2\\x81\\xA7"),
        ('\u{2068}', "\\xE2\\x81\\xA8"),
        ('\u{2069}', "\\xE2\\x81\\xA9"),
    ];
    for (c, want) in cases {
        let s = c.to_string();
        assert_eq!(escape(s.as_bytes()), want, "U+{:04X}", c as u32);
        assert_eq!(unescape(want), Ok(s.into_bytes()));
    }
    // neighbours stay literal
    for c in [
        '\u{061B}', '\u{061D}', '\u{200D}', '\u{2010}', '\u{202F}', '\u{2065}', '\u{206A}',
    ] {
        assert_eq!(escape(c.to_string().as_bytes()), c.to_string());
    }
}
