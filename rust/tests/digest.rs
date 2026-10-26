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

// --- known answers and constructor invariants ---

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

proptest! {
    #[test]
    fn hex_case_insensitive(d in any_digest(), mask in prop::collection::vec(any::<bool>(), 64)) {
        let mixed: String = d.encode(Enc::Hex).chars().zip(mask)
            .map(|(c, up)| if up { c } else { c.to_ascii_lowercase() }).collect();
        prop_assert_eq!(Digest::decode_value(Alg::Sha256, &mixed), Ok(d.clone()));
        prop_assert_eq!(Digest::parse_labelled(&format!("{mixed}:SHA-256")), Ok(d));
    }

    // Both label orders x both encodings; the forward form is built by hand
    // so the test does not reuse the formatter under test.
    #[test]
    fn labelled_roundtrip(d in any_digest(), e in any_enc()) {
        prop_assert_eq!(Digest::decode_value(Alg::Sha256, &d.encode(e)), Ok(d.clone()));
        prop_assert_eq!(Digest::parse_labelled(&d.to_reverse(e)), Ok(d.clone()));
        let fwd = format!("SHA-256:{}", d.encode(e));
        prop_assert_eq!(Digest::parse_labelled(&fwd), Ok(d));
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

// --- strictness table: (input, via parse_labelled?, expected error) ---

#[test]
fn decode_rejects() {
    use DigestError as E;
    let wl = |got| E::WrongLength {
        alg: Alg::Sha256,
        got,
    };
    let ic = |index, ch| E::InvalidChar { index, ch };
    let with = |base: &str, at: usize, c: char| {
        let mut s = base.to_string();
        s.replace_range(at..at + 1, &c.to_string());
        s
    };
    let mut rows: Vec<(String, bool, DigestError)> = vec![
        (String::new(), false, wl(0)),
        (format!(" {EMPTY_B64}"), false, wl(44)),
        (
            format!("{} {}", &EMPTY_B64[..20], &EMPTY_B64[21..]),
            false,
            ic(20, ' '),
        ),
        // padded form of a 32-byte value is a length error, not a decode
        (format!("{EMPTY_B64}="), false, wl(44)),
        // lengths and indices count chars, not bytes
        ("é".repeat(43), false, ic(0, 'é')),
        (format!("{}é", "A".repeat(41)), false, wl(42)),
        // label level
        (EMPTY_B64.into(), true, E::Unlabelled),
        (EMPTY_HEX.into(), true, E::Unlabelled),
        (String::new(), true, E::Unlabelled),
        (
            format!("hash://SHA-256:{EMPTY_B64}"),
            true,
            E::TooManyColons,
        ),
        ("a:b:c".into(), true, E::TooManyColons),
        (
            format!("{EMPTY_B64}:sha-256"),
            true,
            E::UnknownAlg("sha-256".into()),
        ),
        (
            format!("sha-256:{EMPTY_B64}"),
            true,
            E::UnknownAlg(EMPTY_B64.into()),
        ),
        (
            format!("{EMPTY_B64}:MD5"),
            true,
            E::UnknownAlg("MD5".into()),
        ),
        ("AAAA:SHA-256".into(), true, wl(4)),
        ("SHA-256:AAAA".into(), true, wl(4)),
        (
            format!("{}:SHA-256", with(EMPTY_HEX, 3, 'G')),
            true,
            ic(3, 'G'),
        ),
        (
            format!("{}B:SHA-256", &EMPTY_B64[..42]),
            true,
            E::NonCanonical,
        ),
    ];
    // the algorithm name is matched exactly
    for bad in ["sha-256", "Sha-256", "SHA256", "SHA-256 ", " SHA-256", ""] {
        rows.push((
            format!("{EMPTY_B64}:{bad}"),
            true,
            E::UnknownAlg(bad.into()),
        ));
    }
    for c in ('G'..='Z').chain('g'..='z') {
        rows.push((with(EMPTY_HEX, 10, c), false, ic(10, c)));
    }
    for c in ['-', '_', '=', '+', '/'] {
        rows.push((with(EMPTY_HEX, 0, c), false, ic(0, c)));
    }
    for c in ['=', '+', '/'] {
        rows.push((with(EMPTY_B64, 5, c), false, ic(5, c)));
    }
    for (input, labelled, want) in rows {
        let got = if labelled {
            Digest::parse_labelled(&input)
        } else {
            Digest::decode_value(Alg::Sha256, &input)
        };
        assert_eq!(got, Err(want), "{input:?} labelled={labelled}");
    }
}
