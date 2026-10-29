//! `resolve` arguments: labelled digests, `hash://` URIs and the human-name
//! forms of the spec's Digest Naming section.

use ext::digest::{Alg, Digest, Query};

const V: &str = "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ";
const H: &str = "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824";

fn hello() -> Digest {
    Digest::compute(Alg::Sha256, b"hello")
}

fn ok(s: &str) -> Query {
    Query::parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

fn named(s: &str, name: &str) {
    let q = ok(s);
    assert_eq!(q.digest, hello(), "{s}");
    assert_eq!(q.name.as_deref(), Some(name.as_bytes()), "{s}");
}

fn bare(s: &str) {
    let q = ok(s);
    assert_eq!(q.digest, hello(), "{s}");
    assert_eq!(q.name, None, "{s}");
}

#[test]
fn labelled_forms_have_no_name() {
    for s in [
        format!("{V}:SHA-256"),
        format!("SHA-256:{V}"),
        format!("{H}:SHA-256"),
        format!("SHA-256:{}", H.to_lowercase()),
    ] {
        bare(&s);
    }
}

#[test]
fn hash_uri() {
    for s in [
        format!("hash://SHA-256/{V}"),
        format!("HASH://SHA-256/{V}"),
        format!("hAsH://sha-256/{V}"),
        format!("hash://Sha-256/{H}"),
        format!("hash://SHA-256/{}", H.to_lowercase()),
        // Tail starts at the first non-b64ut character and is ignored.
        format!("hash://SHA-256/{V}.png"),
        format!("hash://SHA-256/{V}/more/path"),
        format!("hash://SHA-256/{V}?q=1#frag"),
        format!("hash://SHA-256/{V}="),
        format!("hash://SHA-256/{H}:x"),
    ] {
        bare(&s);
    }
}

#[test]
fn hash_uri_digest_is_case_sensitive() {
    // Same length, canonical, different case in the first character.
    let other = V.replacen('L', "l", 1);
    let q = ok(&format!("hash://SHA-256/{other}"));
    assert_ne!(q.digest, hello());
}

#[test]
fn hash_uri_rejects() {
    for s in [
        "hash://SHA-256".to_string(),
        "hash://SHA-256/".to_string(),
        "hash:///".to_string(),
        format!("hash://SHA-999/{V}"),
        format!("hash:/SHA-256/{V}"),
        format!("hash://SHA-256/{}", &V[..42]),
        // The b64ut prefix runs on into the tail, so the length is wrong.
        format!("hash://SHA-256/{V}abc"),
        // Non-canonical trailing bits.
        format!("hash://SHA-256/{}", V.replace("CQ", "CR")),
        format!("hash://SHA-256/{}", &H[..63]),
    ] {
        assert!(Query::parse(&s).is_err(), "{s}");
    }
}

#[test]
fn alg_names_outside_hash_uri_stay_exact() {
    for s in [
        format!("{V}:sha-256"),
        format!("sha-256:{V}"),
        format!("name:sha-256:{V}"),
    ] {
        assert!(Query::parse(&s).is_err(), "{s}");
    }
}

#[test]
fn human_name_forms() {
    for v in [V, H] {
        named(&format!("SHA-256:{v}:notes.txt"), "notes.txt");
        named(&format!("{v}:SHA-256:notes.txt"), "notes.txt");
        named(&format!("notes.txt:SHA-256:{v}"), "notes.txt");
        named(&format!("notes:SHA-256:{v}.txt"), "notes.txt");
    }
    // Hex in any case.
    named(&format!("n:SHA-256:{}", H.to_lowercase()), "n");
}

#[test]
fn names_may_contain_colons_and_dots() {
    named(&format!("SHA-256:{V}:a:b"), "a:b");
    named(&format!("{V}:SHA-256:a:b:c"), "a:b:c");
    named(&format!("a:b:SHA-256:{V}"), "a:b");
    named(&format!("a.b:SHA-256:{V}.c.d"), "a.b.c.d");
    // The digest sits last: an earlier look-alike belongs to the name.
    let early = format!("x:SHA-256:{V}");
    named(&format!("{early}:SHA-256:{V}"), &early);
}

#[test]
fn name_forms_reject() {
    for s in [
        // empty name, empty extension
        format!("SHA-256:{V}:"),
        format!("{V}:SHA-256:"),
        format!(":SHA-256:{V}"),
        format!("n:SHA-256:{V}."),
        // a name is a filename, so it has no slash
        format!("a/b:SHA-256:{V}"),
        format!("SHA-256:{V}:a/b"),
        format!("{V}:SHA-256:a/b"),
        // no algorithm, or a wrong-length value
        format!("n:m:{V}"),
        format!("n:SHA-256:{}", &V[..42]),
        format!("SHA-256:{}:n", &V[..42]),
        format!("n:SHA-256:{V}x"),
    ] {
        assert!(Query::parse(&s).is_err(), "{s:?}");
    }
}

mod props {
    use super::*;
    use ext::digest::Enc;
    use proptest::prelude::*;

    proptest! {
        /// Every spelling of a digest and a name parses back to both, in
        /// either encoding. Names are lowercase, so they cannot imitate the
        /// uppercase algorithm label.
        #[test]
        fn forms_roundtrip(
            bytes in prop::collection::vec(any::<u8>(), 32),
            stem in "[a-z0-9.:_-]{1,12}",
            ext in "[a-z0-9]{1,4}",
            hex in any::<bool>(),
        ) {
            let d = Digest::from_bytes(Alg::Sha256, &bytes).unwrap();
            let v = d.encode(if hex { Enc::Hex } else { Enc::B64ut });
            let cases = [
                (format!("SHA-256:{v}:{stem}"), stem.clone()),
                (format!("{v}:SHA-256:{stem}"), stem.clone()),
                (format!("{stem}:SHA-256:{v}"), stem.clone()),
                (format!("{stem}:SHA-256:{v}.{ext}"), format!("{stem}.{ext}")),
            ];
            for (arg, name) in cases {
                let q = Query::parse(&arg).unwrap();
                prop_assert_eq!(&q.digest, &d, "{}", arg);
                prop_assert_eq!(q.name, Some(name.into_bytes()), "{}", arg);
            }
            prop_assert_eq!(Query::parse(&format!("hash://SHA-256/{v}.{ext}")).unwrap().digest, d);
        }
    }
}
