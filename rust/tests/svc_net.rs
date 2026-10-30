//! The https backend over plain-http fake backends, library level: status
//! classification (ES-5), headers carry no authority (ES-9), size and time
//! limits (ES-12, ES-13), redirects (ES-14), the resolver and address
//! allow-list wiring (ES-15), the request shape (ES-18), ES-23 on the wire.
//!
//! The TLS side (ES-17) is process level: see `svc_tls.rs`.
//! Run: `cargo test --test svc_net`.

mod svc;

use ext::cache::TmpFile;
use ext::https::{AddrTable, Client, HttpsConfig, Resolver};
use ext::lookup::{self, Backend, Fetched, Limits, Outcome};
use ext::services::ServiceUri;
use proptest::prelude::*;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use svc::fb::{Body, Fb, Latch, Resp};
use svc::*;

/// Names to addresses, and every call counted: seam S2.
#[derive(Default)]
struct Scripted {
    map: HashMap<String, Vec<IpAddr>>,
    calls: Mutex<Vec<(String, u16)>>,
}

struct Shared(Arc<Scripted>);

impl Resolver for Shared {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        self.0.calls.lock().unwrap().push((host.to_string(), port));
        let ips = match host.trim_matches(['[', ']']).parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => self
                .0
                .map
                .get(host)
                .cloned()
                .ok_or_else(|| std::io::Error::other(format!("no such name {host}")))?,
        };
        Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
    }
}

fn client(allow_local: bool, table: AddrTable, names: &[(&str, &[&str])]) -> (Client, Arc<Scripted>) {
    let r = Arc::new(Scripted {
        map: names
            .iter()
            .map(|(n, ips)| (n.to_string(), ips.iter().map(|i| i.parse().unwrap()).collect()))
            .collect(),
        calls: Mutex::default(),
    });
    let cfg = HttpsConfig { allow_http: true, allow_local };
    (Client::new(cfg, Box::new(Shared(r.clone())), table), r)
}

fn local_client() -> Client {
    client(true, AddrTable { allow: vec![], deny: vec![] }, &[]).0
}

fn limits() -> Limits {
    Limits { max_size: 1 << 20, idle: Duration::from_secs(5), total: Duration::from_secs(10) }
}

#[derive(Debug, PartialEq)]
enum Got {
    Hit(Vec<u8>),
    Missing,
    Error(String),
}

fn fetch(c: &Client, uri: &str, want: &[u8], l: &Limits) -> (Got, Duration) {
    let b = c.backend(ServiceUri::parse(uri).unwrap());
    let sink = TmpFile { file: tempfile::tempfile().unwrap(), path: PathBuf::new() };
    let t = Instant::now();
    let r = b.fetch(&fetchable(want), l, sink);
    let took = t.elapsed();
    let got = match r {
        Fetched::Hit(mut t) => {
            let mut v = vec![];
            t.file.seek(SeekFrom::Start(0)).unwrap();
            t.file.read_to_end(&mut v).unwrap();
            Got::Hit(v)
        }
        Fetched::Missing => Got::Missing,
        Fetched::Error(e) => Got::Error(e),
    };
    (got, took)
}

fn is_err(g: &Got) -> bool {
    matches!(g, Got::Error(_))
}

// ----------------------------------------------------------------- ES-5 ----

/// ES-5, exhaustively over every final status 200..=599 (3xx carry a
/// Location to a valid blob). The oracle is written as ranges here. Also: an
/// interim 1xx is ignored, a non-identity Content-Encoding is Error, an empty
/// 200 is a normal candidate. Violators: 403 or a 5xx as Missing, accepting
/// 206 or an unlisted 3xx, honouring gzip, 1xx as final.
#[test]
fn every_final_status_classifies_per_the_table() {
    let b = blob(64, 1);
    let code = Arc::new(AtomicU16::new(200));
    let (c2, b2) = (code.clone(), b.clone());
    let fb = Fb::start("127.0.0.2", move |r| {
        if r.target.starts_with("/ok") {
            return Resp::ok(&b2);
        }
        let n = c2.load(Ordering::SeqCst);
        let resp = Resp::status(n);
        if (300..400).contains(&n) { resp.header("Location", b"/ok") } else { resp }
    });
    let c = local_client();
    for n in 200..=599u16 {
        code.store(n, Ordering::SeqCst);
        let (got, _) = fetch(&c, &fb.base(), &b, &limits());
        let want = match n {
            200 | 301 | 302 | 303 | 307 | 308 => Got::Hit(b.clone()),
            403 | 404 | 410 => Got::Missing,
            _ => Got::Error(String::new()),
        };
        match (&got, &want) {
            (Got::Error(_), Got::Error(_)) => {}
            _ => assert_eq!(got, want, "status {n}"),
        }
    }
}

#[test]
fn interim_gzip_and_empty_bodies() {
    let b = blob(64, 1);
    let c = local_client();
    let b2 = b.clone();
    let fb = Fb::start("127.0.0.2", move |_| Resp { interim: true, ..Resp::ok(&b2) });
    assert_eq!(fetch(&c, &fb.base(), &b, &limits()).0, Got::Hit(b.clone()), "1xx then 200");
    let b2 = b.clone();
    let fb = Fb::start("127.0.0.2", move |_| Resp::ok(&b2).header("Content-Encoding", b"gzip"));
    assert!(is_err(&fetch(&c, &fb.base(), &b, &limits()).0), "gzip is Error");
    let b2 = b.clone();
    let fb = Fb::start("127.0.0.2", move |_| Resp::ok(&b2).header("Content-Encoding", b"identity"));
    assert_eq!(fetch(&c, &fb.base(), &b, &limits()).0, Got::Hit(b.clone()), "identity is fine");
    let fb = Fb::start("127.0.0.2", |_| Resp::ok(b""));
    assert_eq!(fetch(&c, &fb.base(), b"", &limits()).0, Got::Hit(vec![]), "the empty blob is a blob");
    assert_eq!(fetch(&c, &fb.base(), &b, &limits()).0, Got::Hit(vec![]), "an empty candidate is returned, the loop calls it Mismatch");
}

// ----------------------------------------------------------------- ES-9 ----

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    /// ES-9 metamorphic. The same response body with its headers randomised
    /// (except status, framing, Location, Content-Encoding) yields the same
    /// outcome class: Hit exactly when the body is the blob, whatever a
    /// `Digest`, `ETag` or `X-*` header claims. Violator: trusting a claimed
    /// digest to skip or fake the hash.
    #[test]
    fn headers_have_no_authority(
        which in 0usize..8,
        claims in prop::collection::vec(
            (prop_oneof![Just("Digest"), Just("ETag"), Just("Content-MD5"), Just("X-Checksum-Sha256"), Just("X-Anything")],
             prop_oneof![Just("sha-256=BAD"), Just("\"deadbeef\""), Just("good"), Just("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0")]),
            0..5),
    ) {
        let good = blob(64, 5);
        let ms = mutations(&good);
        let served = if which == 0 { good.clone() } else { ms[(which - 1) % ms.len()].1.clone() };
        let claimed = format!("sha-256={}", data_encoding::BASE64.encode(&hex(&sha256_hex(&good))));
        let (s2, cl) = (served.clone(), claims.clone());
        let fb = Fb::start("127.0.0.2", move |_| {
            let mut r = Resp::ok(&s2).header("Digest", claimed.as_bytes()).header("ETag", sha256_hex(&s2).as_bytes());
            for (k, v) in &cl { r = r.header(k, v.as_bytes()); }
            r
        });
        let c = local_client();
        let b = c.backend(ServiceUri::parse(&fb.base()).unwrap());
        let svc = [("svc".to_string(), &b as &dyn Backend)];
        let mut mk = || Ok(TmpFile { file: tempfile::tempfile().unwrap(), path: PathBuf::new() });
        let found = lookup::run(&svc, &fetchable(&good), &limits(), &mut mk).unwrap();
        let want = if served == good { Outcome::Hit } else { Outcome::Mismatch };
        prop_assert_eq!(&found.attempts[0].outcome, &want);
        prop_assert_eq!(found.hit.is_some(), served == good);
    }
}

fn hex(h: &str) -> Vec<u8> {
    data_encoding::HEXUPPER.decode(h.as_bytes()).unwrap()
}

// ---------------------------------------------------------------- ES-12 ----

/// ES-12 with a 64 KiB cap. Exactly the cap is accepted; one byte more is
/// Error whether the length is claimed, chunked or absent; an endless body is
/// cut by the cap long before the total timeout; a claimed length above the
/// cap is Error even if the body is short. Violators: reading to EOF then
/// checking (the endless case runs to the timeout), trusting Content-Length.
#[test]
fn the_size_cap_is_enforced_by_the_client() {
    const CAP: usize = 64 << 10;
    let l = Limits { max_size: CAP as u64, idle: Duration::from_secs(2), total: Duration::from_secs(6) };
    let c = local_client();
    let exact = blob(CAP, 1);
    let over = blob(CAP + 1, 1);
    let serve = |b: Vec<u8>, body: fn(Vec<u8>) -> Body| Fb::start("127.0.0.2", move |_| Resp::status(200).body(body(b.clone())));
    let fb = serve(exact.clone(), Body::Bytes);
    assert_eq!(fetch(&c, &fb.base(), &exact, &l).0, Got::Hit(exact.clone()), "exactly the cap");
    let fb = serve(over.clone(), Body::Bytes);
    assert!(is_err(&fetch(&c, &fb.base(), &over, &l).0), "cap+1 with honest Content-Length");
    let fb = serve(over.clone(), |b| Body::Chunked(b, 4096));
    assert!(is_err(&fetch(&c, &fb.base(), &over, &l).0), "cap+1 without Content-Length");
    let fb = Fb::start("127.0.0.2", move |_| Resp::status(200).body(Body::Lie { claimed: CAP as u64 + 1, sent: vec![1; 10] }));
    assert!(is_err(&fetch(&c, &fb.base(), &exact, &l).0), "claim above the cap, short body");
    let fb = Fb::start("127.0.0.2", |_| Resp::status(200).body(Body::Endless));
    let (got, took) = fetch(&c, &fb.base(), &exact, &l);
    assert!(is_err(&got));
    assert!(took < Duration::from_secs(2), "the cap, not the {:?} total timeout, ended it", l.total);
}

// ---------------------------------------------------------------- ES-13 ----

fn timeout_limits() -> Limits {
    Limits { max_size: 1 << 20, idle: Duration::from_millis(300), total: Duration::from_millis(1500) }
}

/// ES-13, real short timeouts, 500 ms slack. A silent server ends at the idle
/// timeout; a stall after the status line too; a drip that is never idle but
/// always late, and a redirect chain whose hops each take a fraction of the
/// budget, end at the total timeout (the clock spans hops). The lower bounds
/// show each ended for the timeout and not for some other error. Violators:
/// no timeout, idle-only, a timer that resets per hop.
#[test]
fn idle_and_total_timeouts_hold_and_span_hops() {
    let l = timeout_limits();
    let c = local_client();
    let within = |took: Duration, lo_ms: u64, hi_ms: u64, what: &str| {
        assert!(
            took >= Duration::from_millis(lo_ms) && took <= Duration::from_millis(hi_ms + 500),
            "{what}: ended after {took:?}, expected {lo_ms}..{hi_ms} ms (+500 slack)"
        );
    };
    let fb = Fb::start("127.0.0.2", |_| Resp::hang());
    let (g, t) = fetch(&c, &fb.base(), b"x", &l);
    assert!(is_err(&g));
    within(t, 250, 300, "hang");

    let never = Latch::default();
    let fb = Fb::start("127.0.0.2", move |_| Resp::status(200).body(Body::HoldThen(never.clone(), vec![])));
    let (g, t) = fetch(&c, &fb.base(), b"x", &l);
    assert!(is_err(&g));
    within(t, 250, 300, "stall after the status line");

    let fb = Fb::start("127.0.0.2", |_| Resp::status(200).body(Body::Drip { byte: b'a', every: Duration::from_millis(100) }));
    let (g, t) = fetch(&c, &fb.base(), b"x", &l);
    assert!(is_err(&g));
    within(t, 1400, 1500, "drip");

    let b = blob(8, 1);
    let fb = Fb::start("127.0.0.2", move |r| {
        std::thread::sleep(Duration::from_millis(400));
        let host = r.header("host").unwrap().to_string();
        match r.target.strip_prefix("/h").and_then(|n| n.parse::<u32>().ok()) {
            Some(4) => Resp::ok(&b),
            Some(n) => Resp::redirect(302, &format!("http://{host}/h{}", n + 1)),
            None => Resp::redirect(302, &format!("http://{host}/h1")),
        }
    });
    let (g, t) = fetch(&c, &fb.base(), &blob(8, 1), &l);
    assert!(is_err(&g), "five hops of 400 ms cannot fit in 1500 ms");
    within(t, 1400, 1500, "redirect chain");
}

// ---------------------------------------------------------------- ES-14 ----

/// A server redirecting `n` times, alternating absolute and relative forms,
/// then serving the blob.
fn chain(n: u32, b: &[u8]) -> Fb {
    let b = b.to_vec();
    Fb::start("127.0.0.2", move |r| {
        let host = r.header("host").unwrap().to_string();
        let i = r.target.strip_prefix("/h").and_then(|x| x.parse::<u32>().ok()).unwrap_or(0);
        if i >= n { return Resp::ok(&b); }
        let next = if i % 2 == 0 { format!("http://{host}/h{}", i + 1) } else { format!("/h{}", i + 1) };
        Resp::redirect([301, 302, 303, 307, 308][i as usize % 5], &next)
    })
}

/// ES-14. At most 5 hops (6 is Error), absolute and relative Locations, a
/// self-loop ends. Violators: following 6 or more hops, an unbounded loop.
#[test]
fn at_most_five_redirect_hops() {
    let b = blob(40, 2);
    let c = local_client();
    for n in 0..=6u32 {
        let fb = chain(n, &b);
        let (got, _) = fetch(&c, &fb.base(), &b, &limits());
        if n <= 5 {
            assert_eq!(got, Got::Hit(b.clone()), "{n} hops");
        } else {
            assert!(is_err(&got), "{n} hops must be Error");
            assert!(fb.requests().len() <= 6, "no hop past the limit was requested");
        }
    }
    let fb = Fb::start("127.0.0.2", |_| Resp::redirect(302, "/loop"));
    let (got, _) = fetch(&c, &fb.base(), &b, &limits());
    assert!(is_err(&got));
    assert!(fb.requests().len() <= 6, "a self-loop is cut at the hop limit");
}

/// ES-14: a Location must satisfy the services grammar for its scheme and
/// authority, no userinfo, no fragment; other schemes are Error even under
/// AllowHTTP. Violators: following `file:` or `ftp:`, accepting userinfo.
#[test]
fn unacceptable_redirect_targets_are_errors_and_are_not_followed() {
    let b = blob(40, 2);
    let c = local_client();
    let ok = Fb::blob("127.0.0.2", &b);
    let ok_host = ok.addr;
    for loc in [
        format!("http://user:pw@{ok_host}/x"),
        format!("http://{ok_host}/x#frag"),
        "ftp://127.0.0.2/x".into(),
        "file:///etc/passwd".into(),
        "gopher://127.0.0.2/x".into(),
    ] {
        let l2 = loc.clone();
        let fb = Fb::start("127.0.0.2", move |_| Resp::redirect(302, &l2));
        let (got, _) = fetch(&c, &fb.base(), &b, &limits());
        assert!(is_err(&got), "{loc}");
    }
    assert!(ok.requests().is_empty(), "none of those targets was contacted");
    // A query string in a Location is allowed (presigned and CDN redirects).
    let target = format!("http://{ok_host}/x?sig=1");
    let fb = Fb::start("127.0.0.2", move |_| Resp::redirect(302, &target));
    assert_eq!(fetch(&c, &fb.base(), &b, &limits()).0, Got::Hit(b.clone()));
    assert_eq!(ok.requests()[0].target, "/x?sig=1");
}

// ---------------------------------------------------------------- ES-15 ----

/// ES-15 wiring (seams S2 and S3): the hook sees every hop including IP
/// literals, every returned address is judged, the connection goes only to an
/// address that passed, and the resolver is consulted once per hop. Two FBs
/// share a port on 127.0.0.2 ("public": the test table allows only that
/// address) and 127.0.0.3 ("local"). Violators: judging host text, checking
/// only the first hop, re-resolving at connect time, a literal that skips
/// the hook, trying the disallowed address first.
#[test]
fn resolver_and_allow_list_are_wired_on_every_hop() {
    let b = blob(40, 3);
    let public = Fb::blob("127.0.0.2", &b);
    let port = public.addr.port();
    let pb = b.clone();
    let local = Fb::start_on("127.0.0.3", port, move |_| Resp::ok(&pb));
    let table = || AddrTable { allow: vec![("127.0.0.2".parse().unwrap(), 32)], deny: vec![] };
    let names: &[(&str, &[&str])] = &[
        ("pub.test", &["127.0.0.2"]),
        ("pub2.test", &["127.0.0.2"]),
        ("loc.test", &["127.0.0.3"]),
        ("both.test", &["127.0.0.3", "127.0.0.2"]),
    ];
    let (c, r) = client(false, table(), names);
    let uri = |h: &str| format!("http://{h}:{port}/");
    let calls = |r: &Scripted| r.calls.lock().unwrap().len();

    assert_eq!(fetch(&c, &uri("pub.test"), &b, &limits()).0, Got::Hit(b.clone()));
    assert_eq!(calls(&r), 1, "one resolver call for one hop");
    assert!(is_err(&fetch(&c, &uri("loc.test"), &b, &limits()).0));
    assert!(is_err(&fetch(&c, &uri("127.0.0.3"), &b, &limits()).0), "a literal reaches the hook too");
    assert!(r.calls.lock().unwrap().iter().any(|(h, _)| h == "127.0.0.3"));
    assert_eq!(fetch(&c, &uri("both.test"), &b, &limits()).0, Got::Hit(b.clone()), "only the allowed address is used");
    assert!(local.requests().is_empty(), "the local FB saw nothing so far");
    assert_eq!(fetch(&c, &uri("127.0.0.2"), &b, &limits()).0, Got::Hit(b.clone()));

    // Hop wiring: a redirect from the public FB to a disallowed name, then literal.
    for target in [format!("http://loc.test:{port}/x"), format!("http://127.0.0.3:{port}/x")] {
        let redirector = Fb::start("127.0.0.2", move |_| Resp::redirect(302, &target));
        let (got, _) = fetch(&c, &format!("http://pub.test:{}/", redirector.addr.port()), &b, &limits());
        assert!(is_err(&got), "redirect into disallowed space");
    }
    assert!(local.requests().is_empty(), "no hop ever reached the disallowed address");

    // One resolver call per hop: pub.test -> pub2.test is two hops.
    let target = format!("http://pub2.test:{port}/x");
    let redirector = Fb::start("127.0.0.2", move |_| Resp::redirect(302, &target));
    let before = calls(&r);
    assert_eq!(fetch(&c, &format!("http://pub.test:{}/", redirector.addr.port()), &b, &limits()).0, Got::Hit(b.clone()));
    assert_eq!(calls(&r) - before, 2, "resolver consulted exactly once per hop");

    // Control: with AllowLocal the same name connects, so the refusals above
    // were the allow-list and not a broken setup.
    let (c2, _) = client(true, table(), names);
    assert_eq!(fetch(&c2, &uri("loc.test"), &b, &limits()).0, Got::Hit(b.clone()));
    assert_eq!(local.requests().len(), 1);
}

// ---------------------------------------------------------------- ES-18 ----

/// ES-18 and ES-23 on the wire, including a cookie set on a redirect. Only
/// GET, only the five headers, `Accept-Encoding: identity`, no Cookie on any
/// later hop, and the target equals the formula for base, base with trailing
/// slashes, and a template. Violators: a HEAD pre-probe, an added
/// X-Request-Id or Authorization, a cookie jar, gzip in Accept-Encoding, `//`
/// or a lowercase hex digest in the path.
#[test]
fn requests_are_plain_gets_with_the_five_headers() {
    let b = blob(40, 4);
    let c = local_client();
    let (dig, hexd) = (
        data_encoding::BASE64URL_NOPAD.encode(&hex(&sha256_hex(&b))),
        sha256_hex(&b),
    );
    let b2 = b.clone();
    let fb = Fb::start("127.0.0.2", move |r| {
        if r.target.starts_with("/final") {
            Resp::ok(&b2)
        } else {
            Resp::redirect(302, "/final").header("Set-Cookie", b"sid=1; Path=/")
        }
    });
    let hostport = fb.addr.to_string();
    for (line, want_target) in [
        (format!("http://{hostport}"), format!("/SHA-256:{dig}")),
        (format!("http://{hostport}///"), format!("/SHA-256:{dig}")),
        (format!("http://{hostport}/t/{{digest}}"), format!("/t/{dig}")),
        (format!("http://{hostport}/q?a={{alg}}&h={{hex}}"), format!("/q?a=SHA-256&h={hexd}")),
    ] {
        let n0 = fb.requests().len();
        // Each request redirects once, so the target of interest is the first.
        let (got, _) = fetch(&c, &line, &b, &limits());
        assert_eq!(got, Got::Hit(b.clone()), "{line}");
        let reqs = fb.requests();
        assert_eq!(reqs[n0].target, want_target, "{line}");
        for r in &reqs[n0..] {
            assert_eq!(r.method, "GET");
            let allowed = ["host", "user-agent", "accept", "accept-encoding", "connection"];
            for (k, _) in &r.headers {
                assert!(allowed.contains(&k.to_ascii_lowercase().as_str()), "header {k} is not allowed");
            }
            assert_eq!(r.header("accept-encoding"), Some("identity"));
            assert_eq!(r.header("accept"), Some("application/octet-stream"));
            assert!(r.header("user-agent").unwrap_or("").starts_with("ext/"));
            assert!(r.header("cookie").is_none(), "no cookies are sent, even after Set-Cookie");
        }
        assert_eq!(reqs.len() - n0, 2, "one redirect, one final request, no probes");
    }
}
