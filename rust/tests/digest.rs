//! Acceptance tests for plan step 1, section 2.1 (digest codecs).

use ext::digest::{Alg, Digest, DigestError, Enc};
use proptest::prelude::*;

const B64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const EMPTY_HEX: &str = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
const EMPTY_B64: &str = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

fn sha(data: &[u8]) -> Digest {
    Digest::compute(Alg::Sha256, data)
}

fn any_digest() -> impl Strategy<Value = Digest> {
    prop::collection::vec(any::<u8>(), 32)
        .prop_map(|b| Digest::from_bytes(Alg::Sha256, &b).unwrap())
}

fn any_enc() -> impl Strategy<Value = Enc> {
    prop_oneof![Just(Enc::B64ut), Just(Enc::Hex)]
}

// --- Alg ---

#[test]
fn alg_constants() {
    assert_eq!(Alg::ALL, &[Alg::Sha256]);
    assert_eq!(Alg::Sha256.name(), "SHA-256");
    assert_eq!(Alg::Sha256.len(), 32);
    assert_eq!(Alg::Sha256.b64ut_len(), 43);
    assert_eq!(Alg::Sha256.hex_len(), 64);
}

#[test]
fn alg_from_name_is_exact_and_case_sensitive() {
    assert_eq!(Alg::from_name("SHA-256"), Some(Alg::Sha256));
    for bad in ["sha-256", "Sha-256", "SHA256", "SHA-256 ", " SHA-256", ""] {
        assert_eq!(Alg::from_name(bad), None, "{bad:?}");
    }
}

// --- compute / from_bytes / encode ---

#[test]
fn sha256_empty_vector() {
    let d = sha(b"");
    assert_eq!(d.alg(), Alg::Sha256);
    assert_eq!(d.encode(Enc::Hex), EMPTY_HEX);
    assert_eq!(d.encode(Enc::B64ut), EMPTY_B64);
}

#[test]
fn from_bytes_rejects_wrong_length() {
    for n in [0usize, 1, 31, 33, 64] {
        assert_eq!(
            Digest::from_bytes(Alg::Sha256, &vec![0u8; n]),
            Err(DigestError::WrongByteLength {
                alg: Alg::Sha256,
                got: n
            })
        );
    }
    let d = Digest::from_bytes(Alg::Sha256, &[7u8; 32]).unwrap();
    assert_eq!(d.bytes(), &[7u8; 32]);
}

#[test]
fn to_reverse_and_display_shape() {
    let d = sha(b"");
    assert_eq!(d.to_reverse(Enc::B64ut), format!("{EMPTY_B64}:SHA-256"));
    assert_eq!(d.to_reverse(Enc::Hex), format!("{EMPTY_HEX}:SHA-256"));
    assert_eq!(d.to_string(), d.to_reverse(Enc::B64ut));
}

#[test]
fn hex_output_is_uppercase() {
    let h = sha(b"abc").encode(Enc::Hex);
    assert_eq!(h.len(), 64);
    assert!(
        h.bytes()
            .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c)),
        "{h}"
    );
}

proptest! {
    #[test]
    fn encode_lengths_and_alphabet(d in any_digest()) {
        let b = d.encode(Enc::B64ut);
        prop_assert_eq!(b.len(), 43);
        prop_assert!(b.chars().all(|c| B64.contains(c)));
        prop_assert_eq!(d.encode(Enc::Hex).len(), 64);
    }

    #[test]
    fn decode_value_roundtrip(d in any_digest(), e in any_enc()) {
        prop_assert_eq!(Digest::decode_value(Alg::Sha256, &d.encode(e)), Ok(d));
    }

    #[test]
    fn parse_labelled_roundtrip_reverse(d in any_digest(), e in any_enc()) {
        prop_assert_eq!(Digest::parse_labelled(&d.to_reverse(e)), Ok(d));
    }

    #[test]
    fn parse_labelled_roundtrip_forward(d in any_digest(), e in any_enc()) {
        let s = format!("SHA-256:{}", d.encode(e));
        prop_assert_eq!(Digest::parse_labelled(&s), Ok(d));
    }

    #[test]
    fn hex_case_insensitive(d in any_digest(), mask in prop::collection::vec(any::<bool>(), 64)) {
        let mixed: String = d.encode(Enc::Hex).chars().zip(mask)
            .map(|(c, up)| if up { c } else { c.to_ascii_lowercase() }).collect();
        prop_assert_eq!(Digest::decode_value(Alg::Sha256, &mixed), Ok(d.clone()));
        prop_assert_eq!(Digest::parse_labelled(&format!("{mixed}:SHA-256")), Ok(d));
    }

    #[test]
    fn noncanonical_final_char_rejected(d in any_digest(), pick in 0usize..64) {
        let enc = d.encode(Enc::B64ut);
        let c = B64.chars().nth(pick).unwrap();
        let mut s = enc[..42].to_string();
        s.push(c);
        let r = Digest::decode_value(Alg::Sha256, &s);
        if pick % 4 == 0 {
            // only the four low bits carry data; canonical chars have zero pad bits
            prop_assert!(r.is_ok(), "{s} -> {r:?}");
        } else {
            prop_assert_eq!(r, Err(DigestError::NonCanonical));
        }
    }

    #[test]
    fn wrong_lengths_rejected(n in 0usize..200) {
        prop_assume!(n != 43 && n != 64);
        let s = "A".repeat(n);
        prop_assert_eq!(
            Digest::decode_value(Alg::Sha256, &s),
            Err(DigestError::WrongLength { alg: Alg::Sha256, got: n })
        );
    }
}

#[test]
fn every_noncanonical_final_char_rejected_exhaustively() {
    let base = &EMPTY_B64[..42];
    for (i, c) in B64.chars().enumerate() {
        let r = Digest::decode_value(Alg::Sha256, &format!("{base}{c}"));
        if i % 4 == 0 {
            assert!(r.is_ok(), "{c} -> {r:?}");
        } else {
            assert_eq!(r, Err(DigestError::NonCanonical), "{c}");
        }
    }
}

// --- decode_value strictness ---

#[test]
fn decode_value_empty_and_whitespace() {
    assert_eq!(
        Digest::decode_value(Alg::Sha256, ""),
        Err(DigestError::WrongLength {
            alg: Alg::Sha256,
            got: 0
        })
    );
    let padded = format!(" {EMPTY_B64}");
    assert_eq!(
        Digest::decode_value(Alg::Sha256, &padded),
        Err(DigestError::WrongLength {
            alg: Alg::Sha256,
            got: 44
        })
    );
    let inner = format!("{} {}", &EMPTY_B64[..20], &EMPTY_B64[21..]);
    assert_eq!(inner.len(), 43);
    assert!(matches!(
        Digest::decode_value(Alg::Sha256, &inner),
        Err(DigestError::InvalidChar { index: 20, ch: ' ' })
    ));
}

#[test]
fn decode_value_hex_rejects_g_to_z() {
    for c in ('G'..='Z').chain('g'..='z') {
        let mut s = EMPTY_HEX.to_string();
        s.replace_range(10..11, &c.to_string());
        assert_eq!(
            Digest::decode_value(Alg::Sha256, &s),
            Err(DigestError::InvalidChar { index: 10, ch: c }),
            "{c}"
        );
    }
}

#[test]
fn decode_value_hex_rejects_b64_only_chars() {
    for c in ['-', '_', '=', '+', '/'] {
        let mut s = EMPTY_HEX.to_string();
        s.replace_range(0..1, &c.to_string());
        assert!(
            matches!(
                Digest::decode_value(Alg::Sha256, &s),
                Err(DigestError::InvalidChar { index: 0, .. })
            ),
            "{c}"
        );
    }
}

#[test]
fn decode_value_b64_rejects_padding_and_standard_alphabet() {
    for c in ['=', '+', '/'] {
        let mut s = EMPTY_B64.to_string();
        s.replace_range(5..6, &c.to_string());
        assert_eq!(
            Digest::decode_value(Alg::Sha256, &s),
            Err(DigestError::InvalidChar { index: 5, ch: c }),
            "{c}"
        );
    }
    // 44 chars: the padded form of a 32-byte value is a length error, not a decode
    let padded = format!("{EMPTY_B64}=");
    assert_eq!(
        Digest::decode_value(Alg::Sha256, &padded),
        Err(DigestError::WrongLength {
            alg: Alg::Sha256,
            got: 44
        })
    );
}

#[test]
fn decode_value_selects_encoding_by_length() {
    assert_eq!(Digest::decode_value(Alg::Sha256, EMPTY_HEX), Ok(sha(b"")));
    assert_eq!(Digest::decode_value(Alg::Sha256, EMPTY_B64), Ok(sha(b"")));
}

// --- parse_labelled ---

#[test]
fn parse_labelled_both_orders() {
    let want = sha(b"");
    for s in [
        format!("{EMPTY_B64}:SHA-256"),
        format!("{EMPTY_HEX}:SHA-256"),
        format!("SHA-256:{EMPTY_B64}"),
        format!("SHA-256:{EMPTY_HEX}"),
        format!("{}:SHA-256", EMPTY_HEX.to_lowercase()),
    ] {
        assert_eq!(Digest::parse_labelled(&s), Ok(want.clone()), "{s}");
    }
}

#[test]
fn parse_labelled_bare_digest_is_unlabelled() {
    assert_eq!(
        Digest::parse_labelled(EMPTY_B64),
        Err(DigestError::Unlabelled)
    );
    assert_eq!(
        Digest::parse_labelled(EMPTY_HEX),
        Err(DigestError::Unlabelled)
    );
    assert_eq!(Digest::parse_labelled(""), Err(DigestError::Unlabelled));
}

#[test]
fn parse_labelled_hash_uri_is_too_many_colons() {
    assert_eq!(
        Digest::parse_labelled(&format!("hash://SHA-256:{EMPTY_B64}")),
        Err(DigestError::TooManyColons)
    );
    assert_eq!(
        Digest::parse_labelled("a:b:c"),
        Err(DigestError::TooManyColons)
    );
}

#[test]
fn parse_labelled_lowercase_alg_is_unknown() {
    for s in [
        format!("{EMPTY_B64}:sha-256"),
        format!("sha-256:{EMPTY_B64}"),
    ] {
        assert!(
            matches!(Digest::parse_labelled(&s), Err(DigestError::UnknownAlg(_))),
            "{s}"
        );
    }
    assert!(matches!(
        Digest::parse_labelled(&format!("{EMPTY_B64}:MD5")),
        Err(DigestError::UnknownAlg(_))
    ));
}

#[test]
fn parse_labelled_value_errors_propagate() {
    assert_eq!(
        Digest::parse_labelled("AAAA:SHA-256"),
        Err(DigestError::WrongLength {
            alg: Alg::Sha256,
            got: 4
        })
    );
    assert_eq!(
        Digest::parse_labelled("SHA-256:AAAA"),
        Err(DigestError::WrongLength {
            alg: Alg::Sha256,
            got: 4
        })
    );
    let mut bad = EMPTY_HEX.to_string();
    bad.replace_range(3..4, "G");
    assert_eq!(
        Digest::parse_labelled(&format!("{bad}:SHA-256")),
        Err(DigestError::InvalidChar { index: 3, ch: 'G' })
    );
    let nc = format!("{}B", &EMPTY_B64[..42]);
    assert_eq!(
        Digest::parse_labelled(&format!("{nc}:SHA-256")),
        Err(DigestError::NonCanonical)
    );
}

#[test]
fn lengths_and_indices_count_chars_not_bytes() {
    let s = "é".repeat(43);
    assert_eq!(
        Digest::decode_value(Alg::Sha256, &s),
        Err(DigestError::InvalidChar { index: 0, ch: 'é' })
    );
    let s = format!("{}é", "A".repeat(41));
    assert_eq!(
        Digest::decode_value(Alg::Sha256, &s),
        Err(DigestError::WrongLength {
            alg: Alg::Sha256,
            got: 42
        })
    );
}
