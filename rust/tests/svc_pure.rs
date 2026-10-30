//! External services, library level and I/O free: the services grammar
//! (ES-21, ES-23), the address allow-list (ES-15), verification (ES-8, ES-11),
//! the lookup loop (ES-3, ES-4, ES-6) and the exit-code function (ES-7).
//!
//! Run: `cargo test --test svc_pure`. Every test names the violator it turns
//! red; a test that cannot name one does not belong here.

mod svc;

use ext::cache::{TmpFile, Verified};
use ext::digest::Alg;
use ext::https::{permitted, redirect_scheme_allowed, AddrTable};
use ext::lookup::{self, Attempt, Backend, Fetched, Limits, Outcome};
use ext::services::{self, Fetchable, FileError, Scheme, ServiceUri, MAX_SERVICES};
use proptest::prelude::*;
use std::cell::RefCell;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::time::Duration;
use svc::*;

fn tmp_with(content: &[u8]) -> TmpFile {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(content).unwrap();
    // A fetch leaves the cursor at the end; checking must not depend on it.
    TmpFile::anonymous(file)
}

// ---------------------------------------------------------------- ES-21 ----

const PCHAR: &str = "(/|[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-F]{2}){0,12}";

/// A line produced from the ABNF productions, with its normal form.
#[derive(Debug, Clone)]
struct Gen {
    line: String,
    normal: String,
}

fn host() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Za-z0-9]([A-Za-z0-9.-]{0,12}[A-Za-z0-9])?",
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d).to_string()),
        (any::<u128>(), any::<bool>()).prop_map(|(n, up)| {
            let s = format!("[{}]", Ipv6Addr::from(n));
            if up {
                s.to_uppercase()
            } else {
                s
            }
        }),
    ]
}

fn valid_line() -> impl Strategy<Value = Gen> {
    let scheme = prop_oneof![Just("https"), Just("HTTPS"), Just("http"), Just("Http")];
    // Ports 1 and 65535 always appear among the possibilities.
    let port = prop_oneof![
        Just(String::new()),
        Just(":1".to_string()),
        Just(":65535".to_string()),
        (1u32..=65535).prop_map(|p| format!(":{p}")),
    ];
    let base_path = ("/", PCHAR).prop_map(|(a, b)| format!("{a}{b}"));
    let tmpl_path = (
        "/",
        "[A-Za-z0-9/?=&.-]{0,8}",
        prop_oneof![Just("{digest}"), Just("{hex}")],
        "(\\{alg\\}|[a-z/?=&]){0,6}",
    )
        .prop_map(|(a, b, c, d)| format!("{a}{b}{c}{d}"));
    let path = prop_oneof![Just(String::new()), base_path, tmpl_path];
    (scheme, host(), port, path).prop_map(|(s, h, p, path)| Gen {
        line: format!("{s}://{h}{p}{path}"),
        normal: format!("{}://{}{p}{path}", s.to_lowercase(), h.to_lowercase()),
    })
}

proptest! {
    /// ES-21. Violator: a parser that keeps the case of scheme or host, or
    /// whose normal form is not a fixed point (register twice would differ).
    #[test]
    fn grammar_generated_lines_parse_to_their_normal_form(g in valid_line()) {
        let u = ServiceUri::parse(&g.line).expect("a line built from the grammar is accepted");
        prop_assert_eq!(u.as_str(), g.normal.as_str());
        prop_assert_eq!(ServiceUri::parse(u.as_str()).unwrap(), u.clone());
        prop_assert_eq!(u.scheme() == Scheme::Https, g.normal.starts_with("https:"));
    }
}

/// ES-21 mutations outside the production's alphabet, each of which a lax
/// parser accepts. Violators: accepts userinfo, trims whitespace, forgets the
/// length cap, treats an unbalanced `%`, `{` or `[` as text.
#[test]
fn single_point_mutations_of_a_valid_line_are_rejected() {
    let long = format!("https://h/{}", "a".repeat(2049 - 10));
    let at_cap = format!("https://h/{}", "a".repeat(2048 - 10));
    assert!(
        ServiceUri::parse(&at_cap).is_ok(),
        "2048 bytes is within the cap"
    );
    let bad: Vec<(&str, String)> = vec![
        ("userinfo", "https://u:p@example.com/p".into()),
        ("space", "https://exa mple.com/p".into()),
        ("leading space", " https://example.com/p".into()),
        ("tab", "https://example.com/\tp".into()),
        ("cr", "https://example.com/p\r".into()),
        ("nul", "https://example.com/\0p".into()),
        ("non-ascii", "https://exämple.com/p".into()),
        ("bad pct", "https://example.com/%zz".into()),
        ("lone pct", "https://example.com/%4".into()),
        ("empty host", "https:///p".into()),
        ("port 0", "https://example.com:0/".into()),
        ("port 65536", "https://example.com:65536/".into()),
        ("leading-zero port", "https://example.com:0080/".into()),
        ("pct in host", "https://a%41b.example/".into()),
        ("sub-delim in host", "https://a,b.example/".into()),
        ("underscore in host", "https://a_b.example/".into()),
        ("empty port", "https://example.com:/".into()),
        ("fragment", "https://example.com/p#f".into()),
        ("query in base", "https://example.com/p?x=1".into()),
        (
            "unknown placeholder",
            "https://example.com/{x}/{digest}".into(),
        ),
        (
            "template without digest or hex",
            "https://example.com/?a={alg}".into(),
        ),
        ("unbalanced brace", "https://example.com/{digest".into()),
        ("missing slashes", "https:example.com/".into()),
        ("ftp", "ftp://example.com/".into()),
        ("file", "file:///etc/passwd".into()),
        ("backslash", "https://example.com/a\\b".into()),
        ("bracket in path", "https://example.com/a[b".into()),
        ("unclosed ipv6", "https://[::1/".into()),
        ("bad ipv6", "https://[::g]/".into()),
        ("too long", long),
        ("empty line", String::new()),
        ("comment", "# https://example.com/".into()),
    ];
    for (name, line) in bad {
        assert!(
            ServiceUri::parse(&line).is_err(),
            "{name}: {line:?} must be rejected"
        );
    }
}

/// The grammar as an independent oracle, over ASCII: host is non-empty and
/// `dns-name = 1*(ALPHA / DIGIT / "-" / ".")` or a bracketed IPv6 address;
/// the port is `%x31-39 0*4DIGIT` in 1..=65535 (no leading zero).
fn oracle(line: &str) -> bool {
    use regex::Regex;
    let pchar = r"(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-Fa-f]{2})";
    let re = |s: String| Regex::new(&format!(r"\A(?:{s})\z")).unwrap();
    if line.len() > 2048 || !line.bytes().all(|b| (0x21..0x7f).contains(&b)) {
        return false;
    }
    let split = Regex::new(r"(?i)\A(https?)://([^/?#]*)(.*)\z").unwrap();
    let Some(c) = split.captures(line) else {
        return false;
    };
    let (auth, rest) = (&c[2], &c[3]);
    let (host, port) = if let Some(b) = auth.strip_prefix('[') {
        let Some((inner, tail)) = b.split_once(']') else {
            return false;
        };
        if inner.parse::<Ipv6Addr>().is_err() {
            return false;
        }
        (format!("[{inner}]"), tail.to_string())
    } else {
        match auth.split_once(':') {
            Some((h, p)) => (h.to_string(), format!(":{p}")),
            None => (auth.to_string(), String::new()),
        }
    };
    if !auth.starts_with('[') && !re(r"[A-Za-z0-9.-]+".into()).is_match(&host) {
        return false;
    }
    if !port.is_empty() && !re(r":[1-9][0-9]{0,4}".into()).is_match(&port) {
        return false;
    }
    if let Some(p) = port.strip_prefix(':') {
        if p.parse::<u32>().map_or(true, |n| n > 65535) {
            return false;
        }
    }
    let base = re(format!("(?:/|{pchar})*"));
    let tmpl = re(format!(
        r"(?:/|\?|{pchar}|\{{alg\}}|\{{digest\}}|\{{hex\}})*"
    ));
    let has_id = rest.contains("{digest}") || rest.contains("{hex}");
    base.is_match(rest) || (has_id && tmpl.is_match(rest))
}

proptest! {
    /// Harness self-check: the oracle accepts what the generator builds, so
    /// the differential below cannot pass vacuously on an oracle that rejects
    /// everything.
    #[test]
    fn the_oracle_accepts_every_generated_line(g in valid_line()) {
        prop_assert!(oracle(&g.line), "{}", g.line);
    }

    /// ES-21 differential. Near-valid lines (a generated valid line with up to
    /// three random edits) against the grammar-as-regex oracle; this finds
    /// the deviations nobody listed. Violator: any accept/reject disagreement
    /// with the grammar.
    #[test]
    fn parser_agrees_with_the_grammar_oracle_on_near_valid_lines(
        g in valid_line(),
        edits in prop::collection::vec((any::<prop::sample::Index>(), 0usize..3, "[ -~\t\r\u{e4}]"), 0..4),
    ) {
        let mut chars: Vec<char> = g.line.chars().collect();
        for (at, kind, ins) in edits {
            if chars.is_empty() { break; }
            let i = at.index(chars.len());
            let c = ins.chars().next().unwrap();
            match kind { 0 => chars[i] = c, 1 => { chars.remove(i); } _ => chars.insert(i, c) }
        }
        let line: String = chars.into_iter().collect();
        prop_assert_eq!(ServiceUri::parse(&line).is_ok(), oracle(&line), "line {:?}", line);
    }

    /// ES-21: arbitrary text never panics the parser.
    #[test]
    fn parser_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = services::parse_file(&bytes);
        let _ = ServiceUri::parse(&String::from_utf8_lossy(&bytes));
    }

    /// ES-21/22: a valid list survives write and read unchanged, one LF-ended
    /// line per service. Violator: CRLF output, a dropped final LF.
    #[test]
    fn file_render_parse_round_trips(gs in prop::collection::vec(valid_line(), 0..12)) {
        let mut seen = std::collections::HashSet::new();
        let us: Vec<ServiceUri> = gs.iter()
            .filter_map(|g| ServiceUri::parse(&g.line).ok())
            .filter(|u| seen.insert(u.as_str().to_owned()))
            .collect();
        let bytes = services::render_file(&us);
        prop_assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), us.len());
        prop_assert_eq!(services::parse_file(&bytes).unwrap(), us);
    }

    /// ES-21: a fault injected at line k is reported against line k + 1; a
    /// duplicate (after lowercasing scheme and host) against the later copy.
    /// Violator: 0-based numbers, the file's last line, or no number.
    #[test]
    fn file_faults_name_their_one_based_line(k in 1usize..8, j in 0usize..8, which in 0usize..4) {
        let mut lines: Vec<String> = (0..8).map(|i| format!("https://h{i}.example/")).collect();
        let j = j % k;
        lines[k] = match which {
            0 => String::new(),
            1 => "# comment".into(),
            2 => format!("HTTPS://H{j}.Example/"),
            _ => "https://u@h.example/".into(),
        };
        if which == 2 {
            lines[k] = lines[k].replacen("Example", "example", 1);
        }
        let text = format!("{}\n", lines.join("\n"));
        match services::parse_file(text.as_bytes()) {
            Err(FileError::Line { line, .. }) => prop_assert_eq!(line, k + 1),
            other => prop_assert!(false, "expected a line error, got {:?}", other),
        }
    }
}

/// ES-21 whole-file rules the line grammar cannot see. Violators: a missing
/// final LF accepted, CRLF accepted, a 65th service accepted, `https://h`
/// and `https://h/` treated as one line.
#[test]
fn file_level_rules() {
    let n = |i: usize| format!("https://h{i}.example/\n");
    let sixty_four: String = (0..MAX_SERVICES).map(n).collect();
    assert_eq!(
        services::parse_file(sixty_four.as_bytes()).unwrap().len(),
        MAX_SERVICES
    );
    let sixty_five = format!("{sixty_four}{}", n(64));
    assert!(matches!(
        services::parse_file(sixty_five.as_bytes()),
        Err(FileError::Line { line: 65, .. })
    ));
    assert!(
        matches!(
            services::parse_file(b"https://a.example/"),
            Err(FileError::Line { line: 1, .. })
        ),
        "missing final LF"
    );
    assert!(
        matches!(
            services::parse_file(b"https://a.example/\r\n"),
            Err(FileError::Line { line: 1, .. })
        ),
        "CRLF"
    );
    let two = services::parse_file(b"https://h\nhttps://h/\n").unwrap();
    assert_eq!(two.len(), 2, "https://h and https://h/ are different lines");
    assert_eq!(services::parse_file(b"").unwrap(), vec![]);
}

// ---------------------------------------------------------------- ES-23 ----

fn b64ut(data: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(&hex_bytes(&sha256_hex(data)))
}

fn hex_bytes(h: &str) -> Vec<u8> {
    data_encoding::HEXUPPER.decode(h.as_bytes()).unwrap()
}

/// Known answer: SHA-256 of "abc" in b64ut, from the spec's own example.
#[test]
fn the_oracle_agrees_with_the_published_vector() {
    assert_eq!(b64ut(b"abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
    assert_eq!(&sha256_hex(b"")[..8], "E3B0C442");
}

proptest! {
    /// ES-23. The expected target is computed here from the rules, not from
    /// the implementation. Violators: `//` after a trailing slash, escaping
    /// `-`, lowercase hex, a query appended after the path, `{alg}` unreplaced.
    #[test]
    fn request_url_follows_the_formula(
        h in "[a-z]{1,8}\\.example",
        port in prop::option::of(1u16..),
        path in "(/[a-z0-9]{1,5}){0,3}",
        slashes in prop::sample::select(vec![0usize, 1, 3]),
        tmpl in prop::sample::select(vec![
            "", "/x/{digest}", "/{alg}/{hex}", "/f?d={hex}&a={alg}", "/{digest}/{digest}?h={hex}"]),
        data in prop::collection::vec(any::<u8>(), 0..70),
    ) {
        let port = port.map(|p| format!(":{p}")).unwrap_or_default();
        let origin = format!("https://{h}{port}");
        let line = if tmpl.is_empty() { format!("{origin}{path}{}", "/".repeat(slashes)) } else { format!("{origin}{tmpl}") };
        let d = fetchable(&data);
        let (dig, hex) = (b64ut(&data), sha256_hex(&data));
        let want = if tmpl.is_empty() {
            format!("{origin}{path}/SHA-256:{dig}")
        } else {
            format!("{origin}{}", tmpl.replace("{alg}", "SHA-256").replace("{digest}", &dig).replace("{hex}", &hex))
        };
        prop_assert_eq!(ServiceUri::parse(&line).unwrap().request_url(&d), want);
    }
}

// ---------------------------------------------------------------- ES-15 ----

/// ES-15. Known answers on both sides of every registry boundary, plus the
/// space no registry row names (the rule is an allow-list). Violators: a
/// deny-list that forgets 4000::/3, 100.64/10 or 224/4; off-by-one prefixes.
#[test]
fn permitted_known_answers() {
    let t = AddrTable::iana();
    let denied = [
        "4000::1",
        "8000::1",
        "::2",
        "ff02::1",
        "ff0e::1",
        "224.0.0.1",
        "239.255.255.255",
        "::ffff:224.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "0.0.0.0",
        "0.1.2.3",
        "10.0.0.0",
        "10.255.255.255",
        "172.16.0.0",
        "172.31.255.255",
        "100.64.0.0",
        "100.127.255.255",
        "127.0.0.1",
        "127.255.255.255",
        "169.254.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fc00::1",
        "fdff::1",
        "fe80::1",
        "fec0::1",
        "2001:db8::1",
        "2001:0::1",
        "2001:2::1",
        "2002:0a00:0001::1",
        "64:ff9b::808:808",
        "100::1",
    ];
    let allowed = [
        "8.8.8.8",
        "1.1.1.1",
        "9.255.255.255",
        "11.0.0.0",
        "126.255.255.255",
        "128.0.0.1",
        "172.15.255.255",
        "172.32.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "192.0.1.1",
        "192.0.3.1",
        "198.17.255.255",
        "198.20.0.0",
        "203.0.112.255",
        "203.0.114.0",
        "223.255.255.255",
        "2606:4700::1111",
        "2001:4860:4860::8888",
        "2a00:1450::1",
        "::ffff:8.8.8.8",
        "2002:0808:0808::1",
    ];
    for s in denied {
        assert!(!permitted(s.parse().unwrap(), &t), "{s} must be denied");
    }
    for s in allowed {
        assert!(permitted(s.parse().unwrap(), &t), "{s} must be allowed");
    }
}

fn v4(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n)
}

/// ES-15. Teredo (2001::/32) is denied whatever a table allows, and the test
/// is exact: public IPv6 whose second segment happens to be 0 is not Teredo.
/// Violators: the Teredo test matching on the second segment alone (denies
/// 2606:0::), or not matching at all (an allow-all table lets it through).
#[test]
fn teredo_is_denied_and_nothing_else_with_a_zero_second_segment() {
    let all = AddrTable {
        allow: vec![("::".parse().unwrap(), 0), ("0.0.0.0".parse().unwrap(), 0)],
        deny: vec![],
    };
    assert!(
        !permitted("2001:0:4136:e378::1".parse().unwrap(), &all),
        "Teredo"
    );
    assert!(permitted("2606:0:1::1".parse().unwrap(), &all));
    let iana = AddrTable::iana();
    for ok in ["2606:0:1::1", "2a00:0:1::1", "2400:0:1::1"] {
        assert!(
            permitted(ok.parse().unwrap(), &iana),
            "{ok} is public space"
        );
    }
}

/// ES-21. Any number of `{digest}`/`{hex}` placeholders is a template, even
/// or odd. Violator: tracking "has an id placeholder" with xor, which flips
/// back to false on the second one.
#[test]
fn templates_accept_several_placeholders() {
    for l in [
        "https://h.example/{digest}/{hex}",
        "https://h.example/{digest}/{digest}",
        "https://h.example/{hex}/{alg}/{hex}/{digest}",
    ] {
        assert!(ServiceUri::parse(l).is_ok(), "{l}");
    }
}

proptest! {
    /// ES-15 metamorphic: canonicalisation. A v4-mapped v6 is judged exactly as
    /// its v4, and a 6to4 address exactly as its embedded v4, for every v4.
    /// Violator: judging the v6 text (mapped private space allowed), or 6to4
    /// judged as plain 2000::/3 space.
    #[test]
    fn mapped_and_6to4_are_judged_as_their_embedded_v4(n in any::<u32>()) {
        let t = AddrTable::iana();
        let a = v4(n);
        let want = permitted(IpAddr::V4(a), &t);
        prop_assert_eq!(permitted(IpAddr::V6(a.to_ipv6_mapped()), &t), want);
        let o = a.octets();
        let six = Ipv6Addr::new(0x2002, u16::from_be_bytes([o[0], o[1]]), u16::from_be_bytes([o[2], o[3]]), 0, 0, 0, 0, 1);
        prop_assert_eq!(permitted(IpAddr::V6(six), &t), want);
    }

    /// ES-15: every address inside a special-purpose IPv4 block is denied,
    /// whatever its host bits. Blocks are written from the IANA registry here,
    /// independently of the implementation's table.
    #[test]
    fn every_address_in_a_special_v4_block_is_denied(
        blk in prop::sample::select(vec![
            (0u32, 8u32), (0x0a00_0000, 8), (0x6440_0000, 10), (0x7f00_0000, 8), (0xa9fe_0000, 16),
            (0xac10_0000, 12), (0xc000_0000, 24), (0xc000_0200, 24), (0xc0a8_0000, 16),
            (0xc612_0000, 15), (0xc633_6400, 24), (0xcb00_7100, 24), (0xe000_0000, 4), (0xf000_0000, 4)]),
        host in any::<u32>(),
    ) {
        let (base, len) = blk;
        let a = base | (host & (u32::MAX >> len));
        prop_assert!(!permitted(IpAddr::V4(v4(a)), &AddrTable::iana()), "{} is in a special block", v4(a));
    }

    /// ES-15: IPv6 outside 2000::/3 is denied for every top-three-bit prefix
    /// other than 001 (the rule is an allow-list, so no registry row has to
    /// name it). v4-mapped space is canonicalised first and excluded here.
    /// Violator: a deny-list of registry rows only.
    #[test]
    fn ipv6_outside_2000_slash_3_is_denied(
        top in prop::sample::select(vec![0u128, 2, 3, 4, 5, 6, 7]),
        low in any::<u128>(),
    ) {
        let a = Ipv6Addr::from(top << 125 | low >> 3);
        prop_assume!(a.to_ipv4_mapped().is_none());
        prop_assert!(!permitted(IpAddr::V6(a), &AddrTable::iana()), "{a}");
    }
}

/// ES-15 seam S3: the check consults the table it is given, after
/// canonicalisation. Violator: a hard-coded table that ignores the argument.
#[test]
fn permitted_uses_the_table_it_is_given() {
    let t = AddrTable {
        allow: vec![("127.0.0.2".parse().unwrap(), 32)],
        deny: vec![],
    };
    assert!(permitted("127.0.0.2".parse().unwrap(), &t));
    assert!(permitted("::ffff:127.0.0.2".parse().unwrap(), &t));
    assert!(!permitted("127.0.0.3".parse().unwrap(), &t));
    assert!(!permitted("8.8.8.8".parse().unwrap(), &t));
}

/// ES-14 scheme rule, the part of redirect handling no staged server can reach
/// (the https side needs a trusted certificate). Violator: allowing a
/// downgrade without `AllowHTTP`, or refusing a same-scheme hop.
#[test]
fn redirect_scheme_table() {
    use Scheme::*;
    assert!(redirect_scheme_allowed(Https, Https, false));
    assert!(redirect_scheme_allowed(Https, Https, true));
    assert!(!redirect_scheme_allowed(Https, Http, false));
    assert!(redirect_scheme_allowed(Https, Http, true));
    assert!(redirect_scheme_allowed(Http, Https, true));
    assert!(redirect_scheme_allowed(Http, Http, true));
}

// ----------------------------------------------------------- ES-8, ES-11 ----

/// ES-8. The mandatory sizes crossed with every mutation: `Verified` exists
/// exactly when the content is the blob. Violators: hashing a prefix (red on
/// flip-last, append-1), accepting equal size (red on subst), hashing from the
/// cursor (red everywhere), a truncated-file `Ok` (red on truncate-1).
#[test]
fn verified_exists_exactly_for_the_requested_content() {
    let mut sizes = SIZES.to_vec();
    sizes.push(300_000); // beyond any plausible read buffer
    for n in sizes {
        let b = blob(n, 7);
        let want = fetchable(&b);
        let v = Verified::check(tmp_with(&b), &want).unwrap_or_else(|e| panic!("size {n}: {e}"));
        assert_eq!((v.size(), v.digest()), (n as u64, want.digest()));
        for (name, m) in mutations(&b) {
            assert!(
                Verified::check(tmp_with(&m), &want).is_err(),
                "size {n}, {name}: unverified content must not become Verified"
            );
        }
    }
}

#[derive(Debug, PartialEq)]
enum Ev {
    Read(usize),
    Eof,
    Write(usize),
}

struct LogSource {
    data: Vec<u8>,
    pos: usize,
    step: usize,
    log: Rc<RefCell<Vec<Ev>>>,
}

impl Read for LogSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.step).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        self.log
            .borrow_mut()
            .push(if n == 0 { Ev::Eof } else { Ev::Read(n) });
        Ok(n)
    }
}

struct LogSink {
    got: Vec<u8>,
    log: Rc<RefCell<Vec<Ev>>>,
}

impl Write for LogSink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.log.borrow_mut().push(Ev::Write(b.len()));
        self.got.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

proptest! {
    /// ES-11 (seam S4). Nothing is written until the source hit EOF and the
    /// hash is complete; what is written equals the verified content; content
    /// that does not verify writes nothing at all. Violators: streaming while
    /// hashing (a Write before Eof), emitting before the compare, emitting a
    /// mismatching blob.
    #[test]
    fn emit_writes_nothing_before_the_whole_content_verified(
        n in prop::sample::select(SIZES.to_vec()),
        step in 1usize..9000,
        corrupt in prop::option::of(0usize..7),
    ) {
        let good = blob(n, 3);
        let served = match corrupt {
            Some(i) => mutations(&good).get(i).map(|m| m.1.clone()).unwrap_or_else(|| good.clone()),
            None => good.clone(),
        };
        let log = Rc::new(RefCell::new(vec![]));
        let mut src = LogSource { data: served.clone(), pos: 0, step, log: log.clone() };
        let mut sink = LogSink { got: vec![], log: log.clone() };
        let r = lookup::emit_verified(&mut src, tmp_with(b""), &fetchable(&good), &mut sink);
        let ev = log.borrow();
        if served == good {
            prop_assert_eq!(r.unwrap(), n as u64);
            prop_assert_eq!(&sink.got, &good);
            if let Some(first_w) = ev.iter().position(|e| matches!(e, Ev::Write(_))) {
                let eof = ev.iter().position(|e| *e == Ev::Eof).expect("source drained");
                prop_assert!(eof < first_w, "wrote before EOF: {:?}", ev);
            }
        } else {
            prop_assert!(r.is_err());
            prop_assert!(sink.got.is_empty(), "unverified bytes reached stdout");
        }
    }
}

// ------------------------------------------------------ ES-3, ES-4, ES-6 ----

#[derive(Clone, Debug)]
enum Script {
    Good,
    /// Candidate bytes that are not the blob; index into `mutations`.
    Wrong(usize),
    Missing,
    Error,
}

struct Stub {
    id: usize,
    addressable: bool,
    script: Script,
    blob: Vec<u8>,
    calls: Rc<RefCell<Vec<usize>>>,
}

impl Backend for Stub {
    fn addresses(&self, _alg: Alg) -> bool {
        self.addressable
    }
    fn fetch(&self, _d: &Fetchable, _l: &Limits, mut sink: TmpFile) -> Fetched {
        self.calls.borrow_mut().push(self.id);
        let body = match &self.script {
            Script::Good => self.blob.clone(),
            Script::Wrong(i) => {
                let ms = mutations(&self.blob);
                ms[i % ms.len()].1.clone()
            }
            Script::Missing => return Fetched::Missing,
            Script::Error => return Fetched::Error("scripted".into()),
        };
        sink.file().write_all(&body).unwrap();
        sink.file().seek(SeekFrom::End(0)).unwrap();
        Fetched::Hit(sink)
    }
}

fn script() -> impl Strategy<Value = Script> {
    prop_oneof![
        Just(Script::Good),
        (0usize..7).prop_map(Script::Wrong),
        Just(Script::Missing),
        Just(Script::Error),
    ]
}

fn limits() -> Limits {
    Limits {
        max_size: 1 << 20,
        idle: Duration::from_secs(1),
        total: Duration::from_secs(5),
    }
}

proptest! {
    /// ES-3, ES-4, ES-6. Against an independent simulation of the rules:
    /// services are asked in file order and only the unaddressable ones are
    /// skipped; a candidate that is not the blob (including an equal-size one)
    /// is `Mismatch` and the walk goes on; the first verified candidate ends
    /// it and nothing after is called. Violators: asks all and keeps the last
    /// or the fastest, iterates in reverse, ignores `addresses`, stops at the
    /// first mismatch, accepts a candidate on size.
    #[test]
    fn lookup_walks_services_in_order_and_stops_at_the_first_verified(
        specs in prop::collection::vec((any::<bool>(), script()), 0..=MAX_SERVICES),
        len in prop::sample::select(vec![0usize, 1, 64, 4097]),
    ) {
        let the_blob = blob(len, 9);
        let calls = Rc::new(RefCell::new(vec![]));
        let stubs: Vec<Stub> = specs.iter().enumerate().map(|(id, (addressable, script))| Stub {
            id, addressable: *addressable || matches!(script, Script::Good), script: script.clone(),
            blob: the_blob.clone(), calls: calls.clone(),
        }).collect();
        let services: Vec<(String, &dyn Backend)> =
            stubs.iter().map(|s| (format!("svc{}", s.id), s as &dyn Backend)).collect();
        let mut mk = || Ok(tmp_with(b""));
        let found = lookup::run(&services, &fetchable(&the_blob), &limits(), &mut mk).unwrap();

        let mut want: Vec<(String, Outcome)> = vec![];
        let mut want_calls = vec![];
        let mut won = false;
        for s in &stubs {
            let o = if !s.addressable { Outcome::Skipped } else {
                want_calls.push(s.id);
                match &s.script {
                    Script::Good => { won = true; Outcome::Hit }
                    Script::Wrong(_) => Outcome::Mismatch,
                    Script::Missing => Outcome::Missing,
                    Script::Error => Outcome::Error("scripted".into()),
                }
            };
            want.push((format!("svc{}", s.id), o));
            if won { break; }
        }
        let got: Vec<(String, Outcome)> = found.attempts.iter()
            .map(|Attempt { service, outcome }| (service.clone(), match outcome {
                Outcome::Error(_) => Outcome::Error("scripted".into()), o => o.clone() }))
            .collect();
        prop_assert_eq!(got, want);
        prop_assert_eq!(&*calls.borrow(), &want_calls);
        prop_assert_eq!(found.hit.is_some(), won);
        let want_d = fetchable(&the_blob);
        if let Some(v) = found.hit { prop_assert_eq!(v.digest(), want_d.digest()); }
    }
}

// ------------------------------------------------------------------ ES-7 ----

/// ES-7, exhaustively over outcome lists up to length 3 and both flags. The
/// oracle is a restatement of the decision list; its value is catching a
/// transcription slip in any row, including `Skipped`. Violators: exit 1 after
/// an Error, exit 5 above 2, non-zero after a later Hit.
#[test]
fn exit_code_follows_the_decision_list() {
    use Outcome::*;
    let all = [Hit, Missing, Error("e".into()), Mismatch, Skipped];
    let mut lists: Vec<Vec<Outcome>> = vec![vec![]];
    for a in &all {
        lists.push(vec![a.clone()]);
        for b in &all {
            lists.push(vec![a.clone(), b.clone()]);
            for c in &all {
                lists.push(vec![a.clone(), b.clone(), c.clone()]);
            }
        }
    }
    for l in lists {
        for index_failed in [false, true] {
            for write_failed in [false, true] {
                let hit = l.contains(&Hit);
                let bad = l.iter().any(|o| matches!(o, Error(_) | Mismatch));
                let want = if hit && !write_failed {
                    0
                } else if index_failed {
                    2
                } else if bad || write_failed {
                    5
                } else {
                    1
                };
                assert_eq!(
                    lookup::exit_code(&l, index_failed, write_failed),
                    want,
                    "{l:?} index_failed={index_failed} write_failed={write_failed}"
                );
            }
        }
    }
}
