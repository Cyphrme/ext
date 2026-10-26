//! Acceptance tests for plan step 1, section 2.2 (path escaping).

use ext::escape::{escape, unescape, EscapeError};
use proptest::prelude::*;

fn is_forbidden(c: char) -> bool {
    let u = c as u32;
    u < 0x20 || u == 0x7F || (0x80..=0x9F).contains(&u)
}

proptest! {
    #[test]
    fn roundtrip_arbitrary_bytes(x in prop::collection::vec(any::<u8>(), 0..64)) {
        prop_assert_eq!(unescape(&escape(&x)), Ok(x));
    }

    #[test]
    fn roundtrip_arbitrary_strings(s in any::<String>()) {
        prop_assert_eq!(unescape(&escape(s.as_bytes())), Ok(s.into_bytes()));
    }

    #[test]
    fn injective(a in prop::collection::vec(any::<u8>(), 0..24),
                 b in prop::collection::vec(any::<u8>(), 0..24)) {
        prop_assume!(a != b);
        prop_assert_ne!(escape(&a), escape(&b));
    }

    #[test]
    fn output_has_no_control_code_points(x in prop::collection::vec(any::<u8>(), 0..64)) {
        prop_assert!(!escape(&x).chars().any(is_forbidden));
    }

    #[test]
    fn output_has_no_control_code_points_from_strings(s in any::<String>()) {
        prop_assert!(!escape(s.as_bytes()).chars().any(is_forbidden));
    }

    #[test]
    fn plain_printable_utf8_passes_through(s in "[ -\\[\\]-~é日本🙂]{0,32}") {
        prop_assert_eq!(escape(s.as_bytes()), s);
    }

    #[test]
    fn unescape_rejects_backslash_not_followed_by_backslash_or_xnn(
        prefix in "[a-z]{0,5}", c in any::<char>()
    ) {
        prop_assume!(c != '\\' && c != 'x');
        let s = format!("{prefix}\\{c}");
        prop_assert!(unescape(&s).is_err(), "{s:?}");
    }
}

#[test]
fn backslash_is_doubled() {
    assert_eq!(escape(b"a\\b"), "a\\\\b");
}

#[test]
fn c0_and_del_become_uppercase_xnn() {
    assert_eq!(escape(b"\x1B"), "\\x1B");
    assert_eq!(escape(b"\t"), "\\x09");
    assert_eq!(escape(b"\n"), "\\x0A");
    assert_eq!(escape(b"\x00"), "\\x00");
    assert_eq!(escape(b"\x7F"), "\\x7F");
}

#[test]
fn invalid_utf8_bytes_each_escaped() {
    assert_eq!(escape(b"\xFF"), "\\xFF");
    assert_eq!(escape(b"a\xC3"), "a\\xC3");
    assert_eq!(escape(b"\xE2\x82"), "\\xE2\\x82");
}

#[test]
fn c1_controls_escape_every_utf8_byte() {
    // U+0085 NEL is C2 85 in UTF-8
    assert_eq!(escape("\u{85}".as_bytes()), "\\xC2\\x85");
    assert_eq!(escape("\u{80}".as_bytes()), "\\xC2\\x80");
    assert_eq!(escape("\u{9F}".as_bytes()), "\\xC2\\x9F");
}

#[test]
fn other_valid_utf8_passes_through() {
    // U+00A0 is just outside the C1 range
    for s in ["é", "日本語", "🙂", "\u{A0}", "plain /path/to file"] {
        assert_eq!(escape(s.as_bytes()), s);
    }
}

#[test]
fn unescape_accepts_the_two_escape_forms() {
    assert_eq!(unescape("a\\\\b"), Ok(b"a\\b".to_vec()));
    assert_eq!(unescape("\\x1B\\xFF"), Ok(vec![0x1B, 0xFF]));
}

#[test]
fn unescape_rejects_bad_and_truncated_escapes() {
    assert!(matches!(
        unescape("\\q"),
        Err(EscapeError::BadEscape { .. })
    ));
    assert!(unescape("\\xZZ").is_err());
    assert!(unescape("\\x1").is_err());
    assert!(unescape("\\x").is_err());
    assert!(unescape("\\").is_err());
    assert!(unescape("ok\\").is_err());
}
