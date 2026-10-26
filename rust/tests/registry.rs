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

    /// Rendered output has exactly one line per path: an embedded `\n` in a
    /// path is escaped, never emitted raw.
    #[test]
    fn render_is_one_line_per_path(paths in prop::collection::vec(abs_path(), 0..8)) {
        let regs: Vec<_> = paths.iter().map(|p| rp(p)).collect();
        let bytes = render(&regs);
        prop_assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), regs.len());
    }
}

#[test]
fn awkward_bytes_survive() {
    let paths: [&[u8]; 5] = [b"/a\tb", b"/a\nb", b"/a\\b", b"/\xff\xfe", b"/a\\x41"];
    let regs: Vec<_> = paths.iter().map(|p| rp(p)).collect();
    let got = parse(&render(&regs)).unwrap();
    assert_eq!(sorted(got), sorted(regs));
}

#[test]
fn rejects_relative_with_line_number() {
    let r = parse(b"/ok\n/also/ok\nrelative/path\n");
    assert!(matches!(r, Err((3, RegistryErrorKind::Relative))), "{r:?}");
}

#[test]
fn rejects_uris() {
    for line in ["file:///x", "https://example.com/x", "hash://sha256/abc"] {
        let input = format!("/ok\n{line}\n");
        let r = parse(input.as_bytes());
        assert!(matches!(r, Err((2, _))), "{line}: {r:?}");
    }
}

#[test]
fn rejects_lines_failing_unescape() {
    for line in ["/a\\q", "/a\\", "/a\\x4", "/a\\x4g", "/a\\x4a"] {
        let input = format!("/ok\n{line}\n");
        let r = parse(input.as_bytes());
        assert!(
            matches!(r, Err((2, RegistryErrorKind::Escape(_)))),
            "{line}: {r:?}"
        );
    }
}

#[test]
fn ignores_blank_comment_and_duplicate_lines() {
    let r = parse(b"# header\n\n/a\n/a\n  \n/b\n# trailing\n");
    // Whitespace-only is not blank-or-comment: it is a relative path.
    assert!(matches!(r, Err((5, RegistryErrorKind::Relative))), "{r:?}");
    let ok = parse(b"# header\n\n/a\n/a\n/b\n# trailing\n").unwrap();
    assert_eq!(sorted(ok), sorted(vec![rp(b"/a"), rp(b"/b")]));
}

#[test]
fn final_line_without_newline_is_accepted() {
    assert_eq!(parse(b"/a").unwrap(), vec![rp(b"/a")]);
}

#[test]
fn empty_registry_is_empty() {
    assert!(parse(b"").unwrap().is_empty());
}

#[test]
fn from_bytes_rejects_relative_and_dot_segments() {
    use ext::registry::RegPath;
    assert!(matches!(
        RegPath::from_bytes(b"a/b"),
        Err(RegistryErrorKind::Relative)
    ));
    assert!(matches!(
        RegPath::from_bytes(b""),
        Err(RegistryErrorKind::Relative)
    ));
    assert!(RegPath::from_bytes(b"/").is_ok());
}

#[test]
fn from_bytes_collapses_slashes_and_strips_trailing() {
    use ext::registry::RegPath;
    assert_eq!(RegPath::from_bytes(b"/a//b/").unwrap(), rp(b"/a/b"));
    assert_eq!(RegPath::from_bytes(b"//").unwrap(), rp(b"/"));
    assert_eq!(RegPath::from_bytes(b"/a///b//c").unwrap(), rp(b"/a/b/c"));
    assert_eq!(RegPath::from_bytes(b"/a/b/").unwrap().as_bytes(), b"/a/b");
    assert_eq!(RegPath::from_bytes(b"/").unwrap().as_bytes(), b"/");
}

#[test]
fn from_bytes_rejects_dot_segments_as_not_normalised() {
    use ext::registry::RegPath;
    for p in [
        &b"/a/./b"[..],
        b"/a/..",
        b"/..",
        b"/.",
        b"/a/../b",
        b"/a/./",
    ] {
        assert!(
            matches!(
                RegPath::from_bytes(p),
                Err(RegistryErrorKind::NotNormalised)
            ),
            "{p:?}"
        );
    }
    // Dots inside a name are ordinary.
    assert!(RegPath::from_bytes(b"/a/.hidden/..x/y.").is_ok());
}

#[test]
fn from_bytes_rejects_nul() {
    use ext::registry::RegPath;
    assert!(matches!(
        RegPath::from_bytes(b"/a\0b"),
        Err(RegistryErrorKind::Nul)
    ));
}

#[test]
fn parse_applies_normalisation_per_line() {
    assert_eq!(parse(b"/srv/www/\n").unwrap(), vec![rp(b"/srv/www")]);
    assert_eq!(parse(b"/a//b\n").unwrap(), vec![rp(b"/a/b")]);
    // Normalised duplicates are dropped.
    assert_eq!(parse(b"/a/b\n/a//b/\n").unwrap(), vec![rp(b"/a/b")]);
    for bad in ["/srv/../etc", "/a/./b", "/.."] {
        let input = format!("/ok\n{bad}\n");
        let r = parse(input.as_bytes());
        assert!(
            matches!(r, Err((2, RegistryErrorKind::NotNormalised))),
            "{bad}: {r:?}"
        );
    }
}

#[test]
fn parse_rejects_nul_whether_escaped_or_raw() {
    let r = parse(b"/ok\n/a\\x00b\n");
    assert!(matches!(r, Err((2, RegistryErrorKind::Nul))), "{r:?}");
    let r = parse(b"/ok\n/a\0b\n");
    assert!(matches!(r, Err((2, RegistryErrorKind::Nul))), "{r:?}");
}
