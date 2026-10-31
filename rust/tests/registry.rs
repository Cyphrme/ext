//! Acceptance tests for plan §1 "Registry" and §3 `registry.rs`.

mod common;
use common::rp;
use ext::registry::{parse, render, RegistryErrorKind};
use proptest::prelude::*;

fn sorted(mut v: Vec<ext::registry::RegPath>) -> Vec<ext::registry::RegPath> {
    v.sort();
    v
}

fn seg() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        any::<u8>().prop_filter("no NUL or /", |b| *b != 0 && *b != b'/'),
        1..8,
    )
    .prop_filter("not . or ..", |s| s != b"." && s != b"..")
}

fn abs_path() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(seg(), 1..5).prop_map(|segs| {
        let mut p = Vec::new();
        for s in segs {
            p.push(b'/');
            p.extend(s);
        }
        p
    })
}

proptest! {
    #[test]
    fn render_parse_roundtrip(paths in prop::collection::vec(abs_path(), 0..8)) {
        let mut uniq = paths.clone();
        uniq.sort();
        uniq.dedup();
        let regs: Vec<_> = uniq.iter().map(|p| rp(p)).collect();
        let bytes = render(&regs);
        prop_assert_eq!(sorted(parse(&bytes).unwrap()), sorted(regs));
    }
}

#[test]
fn parse_rejects() {
    use RegistryErrorKind as K;
    let rows: &[(&[u8], usize, K)] = &[
        (b"/ok\n/also/ok\nrelative/path\n", 3, K::Relative),
        (b"/ok\nfile:///x\n", 2, K::Relative),
        // Whitespace-only is not blank-or-comment: it is a relative path.
        (b"# header\n\n/a\n/a\n  \n/b\n", 5, K::Relative),
        (b"/ok\n/a\0b\n", 2, K::Nul),
        // Dot segments are rejected, never resolved lexically.
        (b"/ok\n/srv/../etc\n", 2, K::NotNormalised),
        (b"/ok\n/a/./b\n", 2, K::NotNormalised),
        (b"/ok\n/..\n", 2, K::NotNormalised),
        (b"/ok\n/.\n", 2, K::NotNormalised),
        (b"/ok\n/a/..\n", 2, K::NotNormalised),
        (b"/ok\n/a/./\n", 2, K::NotNormalised),
    ];
    for (input, line, kind) in rows {
        let r = parse(input);
        assert!(
            matches!(&r, Err((l, k)) if l == line && k == kind),
            "{:?}: {r:?}",
            String::from_utf8_lossy(input)
        );
    }
    for bad in ["/a\\q", "/a\\", "/a\\x41", "/a\\r", "/a\\T"] {
        let r = parse(format!("/ok\n{bad}\n").as_bytes());
        assert!(
            matches!(r, Err((2, RegistryErrorKind::Escape(_)))),
            "{bad}: {r:?}"
        );
    }
}

#[test]
fn parse_accepts() {
    let rows: &[(&[u8], &[&[u8]])] = &[
        (b"", &[]),
        (b"/a", &[b"/a"]),
        (b"# header\n\n/a\n/a\n/b\n# trailing\n", &[b"/a", b"/b"]),
        // Normalisation is per line; normalised duplicates are dropped.
        (b"/srv/www/\n", &[b"/srv/www"]),
        (b"/a//b\n", &[b"/a/b"]),
        (b"/a/b\n/a//b/\n", &[b"/a/b"]),
        (b"//\n", &[b"/"]),
        (b"/a///b//c\n", &[b"/a/b/c"]),
        (b"/\n", &[b"/"]),
        // TSV escapes only backslash, tab and newline; other bytes are verbatim.
        (b"/a\\tb\\nc\\\\d\n", &[b"/a\tb\nc\\d"]),
        (b"/\xff\xfe\x1b\n", &[b"/\xff\xfe\x1b"]),
        // Dots inside a name are ordinary.
        (b"/a/.hidden/..x/y.\n", &[b"/a/.hidden/..x/y."]),
    ];
    for (input, want) in rows {
        let want: Vec<_> = want.iter().map(|p| rp(p)).collect();
        assert_eq!(
            sorted(parse(input).unwrap()),
            sorted(want),
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }
}
