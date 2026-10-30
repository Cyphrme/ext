//! External services through the real `ext` binary against plain-http fake
//! backends (`AllowHTTP` and `AllowLocal` on, since the binary cannot trust a
//! test CA without `SSL_CERT_FILE`; the TLS path is `svc_tls.rs`).
//!
//! Every test pairs each "nothing was contacted" or "refused" assertion with a
//! control that proves the same setup does reach the service, so none passes
//! on a binary that does nothing. File-mode tests skip loudly under uid 0.
//! Run: `cargo test --test svc_cli`.

mod svc;

use ext::store::Store;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};
use svc::fb::{Body, Fb, Latch, Resp};
use svc::*;

fn honest(b: &[u8]) -> Fb {
    Fb::blob("127.0.0.2", b)
}

fn status_fb(n: u16) -> Fb {
    Fb::start("127.0.0.2", move |_| Resp::status(n))
}

fn setup(fbs: &[&Fb]) -> Env {
    let e = Env::new();
    e.config("");
    e.services(&fbs.iter().map(|f| f.base()).collect::<Vec<_>>());
    e
}

fn hex_of(b: &[u8]) -> String {
    sha256_hex(b)
}

fn cached_name(b: &[u8]) -> String {
    format!("SHA-256/{}", hex_of(b))
}

// ------------------------------------------------------- ES-1, ES-2, ES-32 ----

/// ES-1 and F3. A layer that answers ends the lookup before any service is
/// contacted: the index answers, then the cache answers; a cache record whose
/// file is stale is a miss and the service is asked again. Violators:
/// consulting services first or in parallel, treating "a record exists" as an
/// answer.
#[test]
fn a_local_answer_means_no_service_is_contacted() {
    let (b, c) = (blob(200, 1), blob(300, 2));
    let c_value = label(&c).split(':').next().unwrap().to_string();
    let fb = Fb::start("127.0.0.2", {
        let (b, c) = (b.clone(), c.clone());
        move |r| {
            if r.target.contains(&c_value) {
                Resp::ok(&c)
            } else {
                Resp::ok(&b)
            }
        }
    });
    let env = setup(&[&fb]);
    env.index_file("a", &b);
    let o = env.ext(&["cat", &label(&b)]);
    assert_eq!((o.code, &o.stdout), (0, &b), "index answers: {}", o.stderr);
    assert_eq!(env.ext(&["resolve", &label(&b)]).code, 0);
    assert!(
        fb.requests().is_empty(),
        "the index answered; no service may be contacted"
    );

    let o = env.ext(&["cat", &label(&c)]);
    assert_eq!(
        (o.code, &o.stdout),
        (0, &c),
        "service answers: {}",
        o.stderr
    );
    assert_eq!(fb.requests().len(), 1);
    let o = env.ext(&["cat", &label(&c)]);
    assert_eq!((o.code, &o.stdout), (0, &c));
    assert_eq!(fb.requests().len(), 1, "the cache answered the second time");

    // Stale record: the file's size no longer matches. A miss, so ask again.
    let file = env.store.join("cache").join(cached_name(&c));
    fs::write(&file, &c[..c.len() - 1]).unwrap();
    let o = env.ext(&["cat", &label(&c)]);
    assert_eq!((o.code, &o.stdout), (0, &c), "{}", o.stderr);
    assert_eq!(fb.requests().len(), 2, "a stale record is a miss");
    assert_eq!(
        fs::read(&file).unwrap(),
        c,
        "and the cache holds the verified blob again"
    );
}

/// ES-2. A digest that is truncated, unlabeled, of an unknown algorithm or of
/// the wrong length is locate-only: `cat` rejects it (exit 4) and no service
/// ever sees it. The control shows the same service is reached for a good
/// digest. Violator: forwarding a truncated digest to a service.
#[test]
fn non_fetchable_digests_never_reach_a_service() {
    let b = blob(50, 3);
    let fb = honest(&b);
    let env = setup(&[&fb]);
    let full = label(&b);
    let (value, _) = full.split_once(':').unwrap();
    for arg in [
        format!("{}:SHA-256", &value[..10]),
        value.to_string(),
        format!("{value}:SHA-3"),
        format!("{}:SHA-256", &hex_of(&b)[..30]),
        format!("SHA-256:{}", &value[..42]),
    ] {
        let o = env.ext(&["cat", &arg]);
        assert_eq!(o.code, 4, "{arg}: {}", o.stderr);
        assert!(o.stdout.is_empty());
    }
    assert!(
        fb.requests().is_empty(),
        "no service saw a non-fetchable digest"
    );
    assert_eq!(
        env.ext(&["cat", &full]).code,
        0,
        "control: a full digest does reach the service"
    );
    assert_eq!(fb.requests().len(), 1);
}

/// ES-32. `--offline` contacts nothing: an FB stays silent, and a service
/// whose name does not resolve is not even looked up (online it is an Error,
/// offline the lookup simply misses). Offline hits still work. Violators:
/// contacting a service anyway, resolving names before checking the flag.
#[test]
fn offline_contacts_nobody_and_still_answers_locally() {
    let b = blob(80, 4);
    let fb = honest(&b);
    let env = setup(&[&fb]);
    for cmd in ["cat", "resolve"] {
        let o = env.ext(&[cmd, "--offline", &label(&b)]);
        assert_eq!(o.code, 1, "{cmd}: {}", o.stderr);
    }
    assert!(fb.requests().is_empty());
    assert_eq!(
        env.ext(&["cat", &label(&b)]).code,
        0,
        "control: online reaches the service"
    );
    assert_eq!(
        env.ext(&["cat", "--offline", &label(&b)]).stdout,
        b,
        "offline hit from the cache"
    );
    assert_eq!(fb.requests().len(), 1);

    let env = Env::new();
    env.config("ServiceTimeout: 5000, ServiceIdleTimeout: 5000");
    env.services(&["http://no-such-host.invalid/".to_string()]);
    let miss = label(&blob(5, 9));
    let online = env.ext(&["cat", &miss]);
    assert_eq!(
        online.code, 5,
        "online: the unresolvable service is an Error: {}",
        online.stderr
    );
    assert_eq!(
        env.ext(&["cat", "--offline", &miss]).code,
        1,
        "offline: nobody is consulted"
    );
}

/// ES-15 with the shipped table, through the binary: a service on loopback is
/// refused under the default `AllowLocal=false` (exit 5, nothing reached it)
/// and used once `AllowLocal` is on. Violator: judging nothing, or judging the
/// host text.
#[test]
fn loopback_services_need_allow_local() {
    let b = blob(30, 6);
    let fb = honest(&b);
    let env = Env::new();
    env.config_raw("{ AllowHTTP: true }");
    env.services(&[fb.base()]);
    let o = env.ext(&["cat", &label(&b)]);
    assert_eq!(o.code, 5, "{}", o.stderr);
    assert!(
        fb.requests().is_empty(),
        "F4: a connection to a non-global address"
    );
    env.config("");
    assert_eq!(
        env.ext(&["cat", &label(&b)]).stdout,
        b,
        "control: AllowLocal reaches the same server"
    );
}

// ----------------------------------------------------------------- ES-7 ----

/// ES-7 end to end. The rows of the decision list through the binary, for
/// `cat` and `resolve`. Violators: exit 1 after a 500, exit 5 above 2, a
/// non-zero exit after a later Hit, 4 for a failed service.
#[test]
fn exit_codes_follow_the_decision_list() {
    let b = blob(64, 5);
    let l = label(&b);
    for cmd in ["cat", "resolve"] {
        let rows: Vec<(&str, Vec<Fb>, i32)> = vec![
            ("404", vec![status_fb(404)], 1),
            ("500", vec![status_fb(500)], 5),
            ("404,500", vec![status_fb(404), status_fb(500)], 5),
            ("500,hit", vec![status_fb(500), honest(&b)], 0),
            ("none", vec![], 1),
        ];
        for (name, fbs, want) in rows {
            let env = setup(&fbs.iter().collect::<Vec<_>>());
            let o = env.ext(&[cmd, &l]);
            assert_eq!(o.code, want, "{cmd} [{name}]: {}", o.stderr);
            if name == "500,hit" {
                assert!(
                    o.stderr.contains("ERROR"),
                    "a failure before the hit is still reported: {}",
                    o.stderr
                );
            }
        }
    }
    // A stale index record beats a service failure (2 before 5), but not a hit.
    for (fbs, want) in [
        (vec![status_fb(404)], 2),
        (vec![status_fb(500)], 2),
        (vec![honest(&b)], 0),
    ] {
        let env = setup(&fbs.iter().collect::<Vec<_>>());
        let p = env.index_file("a", &b);
        let mut bad = b.clone();
        bad[10] ^= 1;
        fs::write(&p, &bad).unwrap();
        let o = env.ext(&["cat", &l]);
        assert_eq!(o.code, want, "stale index: {}", o.stderr);
        if want == 2 {
            assert!(
                o.stderr.contains(p.to_str().unwrap()),
                "the failed index record is reported: {}",
                o.stderr
            );
            assert!(o.stdout.is_empty());
        }
    }
}

// ------------------------------------------------------------ ES-6, ES-8 ----

/// ES-6 and ES-8 through the binary. The first service plays each mutation
/// (including an equal-size substitute), the second is honest: exit 0, the
/// honest bytes on stdout, a `SERVICE <uri> MISMATCH` line naming the first,
/// exactly one cached file and record, nothing left in `tmp/`. Violators:
/// stopping at the first mismatch, caching then re-checking, omitting the URI.
#[test]
fn a_lying_service_is_skipped_and_leaves_no_trace() {
    let b = blob(64, 6);
    for (name, bad) in mutations(&b) {
        let liar = Fb::start("127.0.0.2", {
            let bad = bad.clone();
            move |_| Resp::ok(&bad)
        });
        let good = honest(&b);
        let env = setup(&[&liar, &good]);
        let o = env.ext(&["cat", &label(&b)]);
        assert_eq!((o.code, &o.stdout), (0, &b), "{name}: {}", o.stderr);
        assert!(
            o.stderr
                .lines()
                .any(|l| l == format!("SERVICE {} MISMATCH", liar.base())),
            "{name}: stderr was {:?}",
            o.stderr
        );
        assert_eq!(
            env.cache_files(),
            [Path::new(&cached_name(&b)).to_path_buf()],
            "{name}"
        );
        assert_eq!(env.records().len(), 1, "{name}");
        assert!(
            env.tmp_files().is_empty(),
            "{name}: temporary files left behind"
        );
        assert_eq!(good.requests().len(), 1);
    }
}

// ----------------------------------------------------------------- ES-11 ----

/// ES-11. An indexed file changed in place (same size) is skipped and, with
/// nothing else to verify, `cat` exits 2; if the cache holds the blob it
/// answers instead; a corrupt cache file (same size) is evicted and refetched;
/// a reader that closes the pipe early is not an error. Violators: trusting
/// the index or cache file's size, emitting unverified bytes, a non-zero exit
/// on EPIPE.
#[test]
fn cat_hashes_every_blob_it_returns() {
    let b = blob(4096, 7);
    let fb = honest(&b);
    let env = setup(&[&fb]);
    assert_eq!(env.ext(&["cat", &label(&b)]).code, 0);
    let cache_file = env.store.join("cache").join(cached_name(&b));
    let p = env.index_file("a", &b);
    let mut flipped = b.clone();
    flipped[100] ^= 1;
    fs::write(&p, &flipped).unwrap();
    let o = env.ext(&["cat", &label(&b)]);
    assert_eq!(
        (o.code, &o.stdout),
        (0, &b),
        "index file corrupt, cache answers: {}",
        o.stderr
    );
    assert_eq!(fb.requests().len(), 1);

    fs::write(&cache_file, &flipped).unwrap(); // same size, wrong bytes
    let o = env.ext(&["cat", "--offline", &label(&b)]);
    assert_eq!(
        o.code, 2,
        "both local copies fail verification; the index failure decides: {}",
        o.stderr
    );
    assert!(o.stdout.is_empty());
    assert!(
        env.records().is_empty() && !cache_file.exists(),
        "the corrupt cache record and file were evicted"
    );
    fs::write(&cache_file, &flipped).unwrap(); // an orphan: the refetch must replace it
    let o = env.ext(&["cat", &label(&b)]);
    assert_eq!(
        (o.code, &o.stdout),
        (0, &b),
        "corrupt copies skipped, the service answers: {}",
        o.stderr
    );
    assert_eq!(fb.requests().len(), 2, "refetched exactly once");
    assert_eq!(
        fs::read(&cache_file).unwrap(),
        b,
        "the corrupt cache file was replaced by the verified blob"
    );

    // A reader that goes away after one byte.
    let big = blob(1 << 20, 8);
    let env = setup(&[]);
    env.index_file("big", &big);
    let mut child = env
        .command(&["cat", "--offline", &label(&big)], &[])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut one = [0u8; 1];
    std::io::Read::read_exact(child.stdout.as_mut().unwrap(), &mut one).unwrap();
    drop(child.stdout.take());
    assert!(
        child.wait().unwrap().success(),
        "a closed pipe is the consumer's choice"
    );
}

// ----------------------------------------------------------------- ES-16 ----

/// ES-16, ES-22. `http` is refused at registration unless AllowHTTP, and an
/// `http` line already present is an Error naming the service rather than
/// being skipped; with AllowHTTP it registers and fetches. Violators: a
/// silent skip (exit 1), an upgrade to https, accepting at registration.
#[test]
fn http_needs_allow_http() {
    let b = blob(30, 1);
    let fb = honest(&b);
    let env = Env::new();
    env.config_raw("{ AllowLocal: true }");
    let o = env.ext(&["-r", &fb.base()]);
    assert_eq!(o.code, 4, "{}", o.stderr);
    assert_eq!(
        env.services_bytes(),
        None,
        "a refused registration changes nothing"
    );
    env.services(&[fb.base()]);
    let o = env.ext(&["cat", &label(&b)]);
    assert_eq!(
        o.code, 5,
        "an http entry without AllowHTTP is an Error: {}",
        o.stderr
    );
    assert!(
        o.stderr.contains(&fb.base()),
        "naming the service: {}",
        o.stderr
    );
    assert!(fb.requests().is_empty());

    env.config("");
    let _ = fs::remove_file(env.store.join("services"));
    assert_eq!(env.ext(&["-r", &fb.base()]).code, 0);
    assert_eq!(
        env.services_bytes().unwrap(),
        format!("{}\n", fb.base()).into_bytes()
    );
    assert_eq!(env.ext(&["cat", &label(&b)]).stdout, b);
}

// ----------------------------------------------------------------- ES-22 ----

/// ES-22 as metamorphic relations on the file bytes. Register twice equals
/// once; order is registration order; case-different scheme and host is a
/// no-op; path operations leave the services file alone and service
/// operations leave the registry alone; a path that merely contains `://` is
/// a path; register then unregister restores the bytes; `-u` of an absent URI
/// is exit 4 and changes nothing; the 65th service is exit 4 and changes
/// nothing. Violators: classifying by substring, appending duplicates, purging
/// the cache on `-u`, writing the file non-atomically-and-corrupt.
#[test]
fn service_registration_is_idempotent_ordered_and_classified_by_prefix() {
    let env = Env::new();
    env.config("");
    let (a, b) = ("https://a.example/", "https://b.example:8443/p");
    let sv = || env.services_bytes();
    assert_eq!(env.ext(&["-r", a]).code, 0);
    let one = sv().expect("the services file exists after a registration");
    assert_eq!(one, format!("{a}\n").into_bytes());
    assert_eq!(env.ext(&["-r", a]).code, 0);
    assert_eq!(sv().unwrap(), one, "twice equals once");
    assert_eq!(env.ext(&["-r", "HTTPS://A.Example/"]).code, 0);
    assert_eq!(sv().unwrap(), one, "normalisation makes it the same line");
    assert_eq!(env.ext(&["-r", b]).code, 0);
    assert_eq!(
        sv().unwrap(),
        format!("{a}\n{b}\n").into_bytes(),
        "registration order"
    );

    // A path containing `://` is a path.
    let weird = env.work.join("a:").join("b");
    fs::create_dir_all(&weird).unwrap();
    let before = sv();
    let arg = format!("{}/a://b", env.work.display());
    let o = env.ext(&["-r", &arg]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(
        sv(),
        before,
        "path operations leave the services file alone"
    );
    let reg = fs::read(env.store.join("registry")).unwrap();
    assert!(
        String::from_utf8_lossy(&reg).contains("a:/b"),
        "the path was registered"
    );
    assert_eq!(env.ext(&["-r", "https://c.example/"]).code, 0);
    assert_eq!(
        fs::read(env.store.join("registry")).unwrap(),
        reg,
        "service operations leave the registry alone"
    );
    assert_eq!(env.ext(&["-u", "https://c.example/"]).code, 0);
    assert_eq!(sv(), before, "register then unregister restores the bytes");
    let o = env.ext(&["-u", "https://nope.example/"]);
    assert_eq!(o.code, 4, "{}", o.stderr);
    assert_eq!(sv(), before);
    assert_eq!(env.ext(&["-u", a]).code, 0);
    assert_eq!(
        sv().unwrap(),
        format!("{b}\n").into_bytes(),
        "only the named line goes"
    );

    let full: Vec<String> = (0..64).map(|i| format!("https://h{i}.example/")).collect();
    env.services(&full);
    let before = sv();
    assert_eq!(env.ext(&["-r", "https://h64.example/"]).code, 4, "the 65th");
    assert_eq!(sv(), before);
}

/// ES-21 and the owner check on the services file; the file is parsed only
/// when a service is needed. A malformed file names its line (exit 4) when a
/// lookup needs it, but never fails a locally answered `resolve`, `cat
/// --offline` or cache hit; a group-writable file is exit 4. A blob admitted
/// before `-u` stays cached. Violators: parsing eagerly, accepting a
/// group-writable file, purging the cache on unregister.
#[test]
fn the_services_file_is_parsed_lazily_and_checked_for_ownership() {
    let b = blob(60, 2);
    let fb = honest(&b);
    let env = setup(&[&fb]);
    assert_eq!(
        env.ext(&["cat", &label(&b)]).code,
        0,
        "admit through the service"
    );
    let other = label(&blob(60, 3));
    env.services(&[fb.base(), "https://u@bad.example/".to_string()]);
    assert_eq!(
        env.ext(&["cat", &label(&b)]).stdout,
        b,
        "a cache hit never reads the services file"
    );
    assert_eq!(
        env.ext(&["cat", "--offline", &other]).code,
        1,
        "--offline never reads it"
    );
    assert_eq!(env.ext(&["resolve", &label(&b)]).code, 0);
    let o = env.ext(&["cat", &other]);
    assert_eq!(
        o.code, 4,
        "a lookup that needs the file fails: {}",
        o.stderr
    );
    assert!(
        o.stderr.contains("services:2:"),
        "format is services:<line>: <reason>: {}",
        o.stderr
    );

    env.services(&[fb.base()]);
    assert_eq!(env.ext(&["-u", &fb.base()]).code, 0);
    assert_eq!(
        env.ext(&["cat", "--offline", &label(&b)]).stdout,
        b,
        "cached blobs outlive their service"
    );

    if !skip_if_root("group-writable file check") {
        env.services(&[fb.base()]);
        fs::set_permissions(
            env.store.join("services"),
            fs::Permissions::from_mode(0o660),
        )
        .unwrap();
        let o = env.ext(&["-r", "https://x.example/"]);
        assert_eq!(o.code, 4, "{}", o.stderr);
    }
}

// ----------------------------------------------------------------- ES-20 ----

/// ES-20. A 401 with a hostile challenge is an Error naming the service; one
/// request, no credentials. Violator: retrying with Authorization.
#[test]
fn a_401_is_an_error_and_no_credentials_are_sent() {
    let fb = Fb::start("127.0.0.2", |_| {
        Resp::status(401).header("WWW-Authenticate", b"Basic realm=\"x\", Bearer")
    });
    let env = setup(&[&fb]);
    let o = env.ext(&["cat", &label(b"x")]);
    assert_eq!(o.code, 5, "{}", o.stderr);
    assert!(o.stderr.contains(&fb.base()), "{}", o.stderr);
    let reqs = fb.requests();
    assert_eq!(reqs.len(), 1);
    assert!(reqs[0].header("authorization").is_none());
}

// ----------------------------------------------------------------- ES-19 ----

/// ES-19. Everything printed on stderr is LF or printable ASCII: escape bytes
/// in a file name (from the filesystem) and in a server's reason phrase become
/// `\xNN`, and a literal backslash becomes `\x5c`, so the escaping is
/// injective. Violators: escaping only bytes below 0x20 (0x9B and 0xFF pass),
/// printing the reason phrase raw, leaving a backslash alone.
#[test]
fn untrusted_text_on_stderr_is_escaped() {
    let ok = |s: &str| s.bytes().all(|b| b == b'\n' || (0x20..=0x7e).contains(&b));
    let b = blob(64, 3);
    let env = setup(&[]);
    let name = "e\x1b[31m\rcsi\u{9b}x\\y";
    let p = env.index_file(name, &b);
    let mut bad = b.clone();
    bad[3] ^= 1;
    fs::write(&p, &bad).unwrap();
    let o = env.ext(&["cat", &label(&b)]);
    assert_eq!(o.code, 2, "{}", o.stderr);
    assert!(ok(&o.stderr), "raw control bytes on stderr: {:?}", o.stderr);
    for want in ["\\x1b", "\\x0d", "\\x5c"] {
        assert!(
            o.stderr.contains(want),
            "{want} missing from {:?}",
            o.stderr
        );
    }

    // Bytes the HTTP parser lets through: HTAB, 0x80..0xFF (incl. a C1 byte
    // and U+202E) and a backslash. Control bytes like ESC never get this far,
    // so the file-name half above covers them.
    let reason = b"t\tab\x9b\xff\xe2\x80\xae\\x41 end".to_vec();
    let fb = Fb::start("127.0.0.2", move |_| {
        Resp::status(500)
            .reason(&reason)
            .header("X-Msg", b"v\t\xff")
    });
    let env = setup(&[&fb]);
    let o = env.ext(&["cat", &label(&b)]);
    assert_eq!(o.code, 5, "{}", o.stderr);
    assert!(
        ok(&o.stderr),
        "service text reached the terminal unescaped: {:?}",
        o.stderr
    );
    assert!(
        !o.stderr.contains("\\x41"),
        "a raw backslash in service text must print as \\x5c: {:?}",
        o.stderr
    );
    assert!(o.stderr.contains(&fb.base()));
}

// ---------------------------------------------------------- ES-24, ES-30 ----

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// ES-24 through the binary under `umask 0`: directories 0700, files 0600, the
/// in-flight file 0600 while a hung fetch holds it open, and a hostile server
/// (`Content-Disposition`, a `Location` with `..`) creates nothing but
/// `cache/SHA-256/<HEX>`. Violators: default modes under the umask, naming a
/// file from a header or a URL.
#[test]
fn cache_files_are_private_and_named_only_by_digest() {
    let b = blob(100, 5);
    let b2 = b.clone();
    let fb = Fb::start("127.0.0.2", move |r| {
        if r.target.starts_with("/y") {
            Resp::ok(&b2).header("Content-Disposition", b"attachment; filename=\"../../x\"")
        } else {
            Resp::redirect(302, "/../../y")
        }
    });
    let env = setup(&[&fb]);
    let before: Vec<_> = fs::read_dir(&env.base)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let mut c = std::process::Command::new("sh");
    c.arg("-c")
        .arg("umask 0; exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_ext"))
        .arg("--d")
        .arg(&env.store)
        .args(["cat", &label(&b)]);
    let o = run(c, Duration::from_secs(30));
    assert_eq!((o.code, &o.stdout), (0, &b), "{}", o.stderr);
    assert_eq!(
        env.cache_files(),
        [Path::new(&cached_name(&b)).to_path_buf()]
    );
    assert_eq!(mode(&env.store.join("cache").join(cached_name(&b))), 0o600);
    for d in ["cache", "cache/SHA-256", "cache/tmp"] {
        assert_eq!(mode(&env.store.join(d)), 0o700, "{d}");
    }
    let after: Vec<_> = fs::read_dir(&env.base)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(before, after, "nothing was created beside the store");

    // The in-flight file while the fetch is held open.
    let latch = Latch::default();
    let hold = Fb::start("127.0.0.2", {
        let l = latch.clone();
        move |_| Resp::status(200).body(Body::HoldThen(l.clone(), vec![]))
    });
    let env = setup(&[&hold]);
    let mut c = std::process::Command::new("sh");
    c.arg("-c")
        .arg("umask 0; exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_ext"))
        .arg("--d")
        .arg(&env.store)
        .args(["cat", &label(&b)]);
    let child = c
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let t0 = Instant::now();
    while hold.requests().is_empty() && t0.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(200));
    let tmps = env.tmp_files();
    assert_eq!(tmps.len(), 1, "one in-flight file while the fetch is open");
    assert_eq!(mode(&tmps[0]), 0o600);
    latch.fire();
    let mut child = child;
    child.kill().ok();
    child.wait().ok();
}

// ---------------------------------------------------------------- ES-25 ----

/// ES-25. If the verified blob cannot be admitted (read-only store, or the
/// store lock busy past the 5 s timeout) the lookup stops with exit 5, a clear
/// error, nothing on stdout and no temporary left; it never reports 1, because
/// the blob may exist. A locally answerable `resolve` still exits 0. Violators:
/// exit 1 on a private-copy failure, waiting on the lock without a bound,
/// delivering bytes that were not admitted.
#[test]
fn an_admission_that_cannot_happen_is_exit_5_not_1() {
    let b = blob(64, 9);
    let fb = honest(&b);
    let env = setup(&[&fb]);
    let idx_digest = label(&blob(10, 1));
    // Busy lock: held here for the whole call.
    let lock = Store::open(&env.store).unwrap().lock().unwrap();
    let (cat, resolve) = std::thread::scope(|s| {
        let h = s.spawn(|| env.ext_env(&["cat", &label(&b)], &[], Duration::from_secs(8)));
        let r = env.ext_env(&["resolve", &label(&b)], &[], Duration::from_secs(8));
        (h.join().unwrap(), r)
    });
    drop(lock);
    for (name, o) in [("cat", &cat), ("resolve", &resolve)] {
        assert_eq!(o.code, 5, "{name} against a busy lock: {}", o.stderr);
        assert!(
            o.elapsed >= Duration::from_millis(4500) && o.elapsed < Duration::from_secs(7),
            "{name}: the 5 s busy timeout was not honoured: {:?}",
            o.elapsed
        );
        assert!(o.stdout.is_empty(), "{name}: nothing delivered");
        assert!(!o.stderr.is_empty());
    }
    assert!(env.tmp_files().is_empty(), "no temporary left");
    assert_eq!(
        env.ext(&["cat", &label(&b)]).code,
        0,
        "control: with the lock free the same lookup works"
    );

    if skip_if_root("read-only store") {
        return;
    }
    let env = setup(&[&fb]);
    env.index_file("idx", &blob(10, 1));
    fs::create_dir_all(env.store.join("cache/tmp")).unwrap();
    fs::create_dir_all(env.store.join("cache/SHA-256")).unwrap();
    for d in ["cache/SHA-256", "cache/tmp", "cache", ""] {
        fs::set_permissions(env.store.join(d), fs::Permissions::from_mode(0o500)).unwrap();
    }
    let svc = env.ext(&["cat", &label(&b)]);
    let idx = env.ext(&["cat", &idx_digest]);
    let res = env.ext(&["resolve", &label(&b)]);
    let local = env.ext(&["resolve", &idx_digest]);
    for d in ["", "cache", "cache/tmp", "cache/SHA-256"] {
        fs::set_permissions(env.store.join(d), fs::Permissions::from_mode(0o700)).unwrap();
    }
    for (name, o) in [
        ("cat, service hit", &svc),
        ("cat, index hit", &idx),
        ("resolve, service hit", &res),
    ] {
        assert_eq!(o.code, 5, "{name}: {}", o.stderr);
        assert!(o.stdout.is_empty(), "{name}: nothing may be delivered");
    }
    assert_eq!(
        local.code, 0,
        "an index hit under resolve needs no write: {}",
        local.stderr
    );
}

// ---------------------------------------------------------------- ES-27 ----

/// ES-27. A cache-hit `resolve` neither fails nor waits when another process
/// holds the lock, and leaves the record's atime alone. Violators: blocking on
/// the lock (3 s or more), failing the lookup.
#[test]
fn a_cache_hit_never_waits_for_the_lock() {
    let b = blob(64, 4);
    let fb = honest(&b);
    let env = setup(&[&fb]);
    assert_eq!(env.ext(&["resolve", &label(&b)]).code, 0, "admit");
    let before = env.records();
    let lock = Store::open(&env.store).unwrap().lock().unwrap();
    let o = env.ext(&["resolve", &label(&b)]);
    drop(lock);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.elapsed < Duration::from_secs(1), "waited {:?}", o.elapsed);
    assert_eq!(env.records(), before, "the touch was skipped");
}

// ----------------------------------------------------------------- ES-28 ----

/// ES-28. Cached blobs are not in `list`, not scanned and not hashed by
/// `check` or `rebuild`, even when the registered root contains the store. With
/// every cache file chmod 000, a scan that opened them would report an
/// error. Violator: a scan descending into `cache/`.
#[test]
fn the_cache_is_invisible_to_list_and_scans() {
    if skip_if_root("chmod 000 is invisible to uid 0") {
        return;
    }
    let b = blob(64, 1);
    let fb = honest(&b);
    let env = setup(&[&fb]);
    env.index_file("w", b"work");
    assert_eq!(
        env.ext(&["-r", env.base.to_str().unwrap()]).code,
        0,
        "register the directory holding the store"
    );
    let list0 = env.ext(&["list"]).stdout;
    assert_eq!(env.ext(&["cat", &label(&b)]).code, 0, "admit a blob");
    for f in env.cache_files() {
        fs::set_permissions(
            env.store.join("cache").join(f),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();
    }
    assert_eq!(
        env.ext(&["list"]).stdout,
        list0,
        "list is unchanged by the cache"
    );
    for cmd in ["check", "rebuild"] {
        let o = env.ext(&[cmd]);
        assert_eq!(o.code, 0, "{cmd}: {}", o.stderr);
        assert!(
            !String::from_utf8_lossy(&o.stdout).contains("cache"),
            "{cmd} reported a cache path"
        );
    }
    for f in env.cache_files() {
        fs::set_permissions(
            env.store.join("cache").join(f),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
}

// ----------------------------------------------------------------- ES-29 ----

/// ES-29. The write lock is not held across a network wait: while one `cat` is
/// stuck waiting for its service (latch closed), `-r` and `check` complete;
/// then the fetch finishes. Four concurrent lookups of one digest all succeed
/// and leave one record. Violators: the lock held across the fetch (the
/// register blocks), a double record.
#[test]
fn the_lock_is_not_held_while_waiting_on_a_service() {
    let b = blob(64, 8);
    let latch = Latch::default();
    let fb = Fb::start("127.0.0.2", {
        let (l, b) = (latch.clone(), b.clone());
        move |_| Resp::status(200).body(Body::HoldThen(l.clone(), b.clone()))
    });
    let env = setup(&[&fb]);
    let child = env
        .command(&["cat", &label(&b)], &[])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let t0 = Instant::now();
    while fb.requests().is_empty() && t0.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(fb.requests().len(), 1, "the fetch is in flight");
    let reg = env.ext_env(
        &["-r", env.work.to_str().unwrap()],
        &[],
        Duration::from_secs(5),
    );
    let chk = env.ext_env(&["check"], &[], Duration::from_secs(5));
    assert_eq!(
        (reg.code, chk.code),
        (0, 0),
        "{} {}",
        reg.stderr,
        chk.stderr
    );
    latch.fire();
    let out = child.wait_with_output().unwrap();
    assert_eq!((out.status.code(), &out.stdout), (Some(0), &b));

    let fb = honest(&b);
    let env = setup(&[&fb]);
    let outs: Vec<Out> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..4)
            .map(|_| s.spawn(|| env.ext(&["cat", &label(&b)])))
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for o in &outs {
        assert_eq!((o.code, &o.stdout), (0, &b), "{}", o.stderr);
    }
    assert_eq!(env.records().len(), 1);
    assert_eq!(env.cache_files().len(), 1);
}

// ------------------------------------------------------- ES-12, ES-13, ES-31 ----

/// ES-12, ES-13 and the config wiring: `ServiceMaxSize` and `ServiceIdleTimeout`
/// from the config file govern the fetch (bytes and milliseconds in this
/// suite; the spec text leaves the units open). Exactly the cap is fine, one
/// more is exit 5; a silent server ends at the idle timeout, naming the
/// service. Violator: ignoring the config and using the defaults.
#[test]
fn config_limits_govern_the_fetch() {
    let ok = blob(64, 1);
    let over = blob(65, 1);
    let env = Env::new();
    env.config(
        "ServiceMaxSize: 64, CacheCapacity: 1024, ServiceIdleTimeout: 300, ServiceTimeout: 1500",
    );
    let fb = honest(&ok);
    env.services(&[fb.base()]);
    assert_eq!(env.ext(&["cat", &label(&ok)]).stdout, ok, "exactly the cap");
    let fb = honest(&over);
    env.services(&[fb.base()]);
    let o = env.ext(&["cat", &label(&over)]);
    assert_eq!(o.code, 5, "one byte over the cap: {}", o.stderr);

    let hang = Fb::start("127.0.0.2", |_| Resp::hang());
    env.services(&[hang.base()]);
    // A digest the cache does not hold: `ok` was admitted above, and a cache
    // hit (ES-1) would answer without contacting the hanging service.
    let o = env.ext_env(&["cat", &label(&over)], &[], Duration::from_secs(8));
    assert_eq!(o.code, 5, "{}", o.stderr);
    assert!(
        o.elapsed < Duration::from_secs(3),
        "idle timeout of 300 ms ended it after {:?}",
        o.elapsed
    );
    assert!(o.stderr.contains(&hang.base()), "{}", o.stderr);
}

/// ES-13 and ES-12 config wiring, second half: `ServiceTimeout` bounds a
/// server that is never idle (a slow drip), and `CacheCapacity` reaches the
/// cache (two blobs that cannot both fit leave only the newer one).
/// Violators: ignoring either key and using the default.
#[test]
fn service_timeout_and_cache_capacity_reach_the_binary() {
    let drip = Fb::start("127.0.0.2", |_| {
        Resp::status(200).body(Body::Drip {
            byte: b'a',
            every: Duration::from_millis(100),
        })
    });
    let env = Env::new();
    env.config("ServiceTimeout: 1500, ServiceIdleTimeout: 30000");
    env.services(&[drip.base()]);
    let o = env.ext_env(&["cat", &label(b"x")], &[], Duration::from_secs(10));
    assert_eq!(o.code, 5, "{}", o.stderr);
    assert!(
        o.elapsed >= Duration::from_millis(1400) && o.elapsed < Duration::from_millis(2500),
        "{:?}",
        o.elapsed
    );

    let (a, b) = (blob(60, 1), blob(60, 2));
    let (a_val, b2) = (label(&a).split(':').next().unwrap().to_string(), b.clone());
    let a2 = a.clone();
    let fb = Fb::start("127.0.0.2", move |r| {
        if r.target.contains(&a_val) {
            Resp::ok(&a2)
        } else {
            Resp::ok(&b2)
        }
    });
    let env = Env::new();
    env.config("CacheCapacity: 100, ServiceMaxSize: 64");
    env.services(&[fb.base()]);
    for blob in [&a, &b] {
        let o = env.ext(&["cat", &label(blob)]);
        assert_eq!((o.code, &o.stdout), (0, blob), "{}", o.stderr);
    }
    assert_eq!(
        env.cache_files(),
        [Path::new(&cached_name(&b)).to_path_buf()],
        "the older blob was evicted to honour CacheCapacity"
    );
    assert_eq!(env.records().len(), 1);
}

/// ES-31. `ServiceMaxSize` above `CacheCapacity` is a configuration error
/// naming both keys; equal is accepted. Violator: silently clamping.
#[test]
fn service_max_size_may_not_exceed_cache_capacity() {
    let e = ext::config::parse(b"{ CacheCapacity: 10, ServiceMaxSize: 11 }").expect_err("11 > 10");
    let msg = e.to_string();
    assert!(
        msg.contains("CacheCapacity") && msg.contains("ServiceMaxSize"),
        "{msg}"
    );
    assert!(ext::config::parse(b"{ CacheCapacity: 10, ServiceMaxSize: 10 }").is_ok());
}

/// ES-25 with a write-ahead log the store's owner never checkpointed: a
/// crash, or a store made read-only (or bind-mounted read-only) while live,
/// leaves committed rows only in `index.db-wal`. A read-only `resolve` must
/// see them, or fail loudly; it must never answer "absent" (exit 1).
/// Violator: a read-only open that ignores the WAL (SQLite `immutable`).
#[test]
fn a_read_only_store_reads_its_uncheckpointed_wal() {
    if skip_if_root("read-only store") {
        return;
    }
    let env = setup(&[]);
    // A second connection keeps the WAL from being checkpointed and removed
    // when ext closes its own.
    let holder = rusqlite::Connection::open(env.store.join("index.db")).unwrap();
    holder
        .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get::<_, String>(0))
        .unwrap();
    // An open read transaction pins the old snapshot, so ext's closing
    // checkpoint cannot move the new rows into index.db.
    holder.execute_batch("BEGIN").unwrap();
    let _: i64 = holder
        .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
        .unwrap();
    let b = blob(10, 1);
    let p = env.index_file("f", &b);
    let wal = env.store.join("index.db-wal");
    assert!(
        fs::metadata(&wal).map(|m| m.len()).unwrap_or(0) > 0,
        "fixture: the record must be in a non-empty WAL: {:?}",
        fs::read_dir(&env.store)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), e.metadata().unwrap().len())
            })
            .collect::<Vec<_>>()
    );
    let found_or_loud = |o: &Out, what: &str| {
        assert_ne!(o.code, 1, "{what}: answered absent: {}", o.stderr);
        if o.code == 0 {
            assert!(
                String::from_utf8_lossy(&o.stdout).contains(p.to_str().unwrap()),
                "{what}"
            );
        } else {
            assert!(!o.stderr.is_empty(), "{what}: failed without saying why");
        }
    };

    fs::set_permissions(&env.store, fs::Permissions::from_mode(0o500)).unwrap();
    let with_shm = env.ext(&["resolve", &label(&b)]);
    fs::set_permissions(&env.store, fs::Permissions::from_mode(0o700)).unwrap();
    found_or_loud(&with_shm, "WAL and -shm present");
    assert_eq!(
        with_shm.code, 0,
        "with its -shm the WAL is readable: {}",
        with_shm.stderr
    );

    // The same files without the -shm, which a read-only directory cannot
    // recreate.
    let env2 = setup(&[]);
    for f in ["index.db", "index.db-wal"] {
        fs::copy(env.store.join(f), env2.store.join(f)).unwrap();
    }
    fs::copy(env.store.join("registry"), env2.store.join("registry")).unwrap();
    fs::set_permissions(&env2.store, fs::Permissions::from_mode(0o500)).unwrap();
    let no_shm = env2.ext(&["resolve", &label(&b)]);
    fs::set_permissions(&env2.store, fs::Permissions::from_mode(0o700)).unwrap();
    found_or_loud(&no_shm, "WAL without -shm");
    drop(holder);
}

/// ES-14. A relative `Location` is resolved against the current URL with its
/// dot segments removed, as a reference resolver would: `/x/y/../z/./w` is
/// `/x/z/w`, and `p/q/../../r` from the root is `/r`. Violator: a broken dot
/// segment remover (wrong segment boundaries, which can loop forever; the
/// run is killed at its limit and reported as a failure).
#[test]
fn relative_redirects_resolve_dot_segments() {
    let b = blob(40, 6);
    for (first, landing) in [
        ("/x/y/../z/./w", "/x/z/w"),
        ("p/q/../../r", "/r"),
        ("/a/b/c/../../d", "/a/d"),
        ("9:x", "/9:x"),
        ("a_b:c", "/a_b:c"),
    ] {
        let (b2, first2, landing2) = (b.clone(), first.to_string(), landing.to_string());
        let fb = Fb::start("127.0.0.2", move |r| {
            if r.target == landing2 {
                Resp::ok(&b2)
            } else if r.target.starts_with("/SHA-256:") {
                Resp::redirect(302, &first2)
            } else {
                Resp::status(404)
            }
        });
        let env = setup(&[&fb]);
        let o = env.ext_env(&["cat", &label(&b)], &[], Duration::from_secs(10));
        assert_eq!((o.code, &o.stdout), (0, &b), "{first}: {}", o.stderr);
    }
}

/// ES-6, ES-25. A failed attempt prints `SERVICE <uri> ERROR <message>` with a
/// message that says why: a timeout says so, a refused connection carries the
/// OS cause. Violators: an empty or placeholder message.
#[test]
fn service_errors_say_why() {
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.2:0").unwrap();
        format!("http://{}/", l.local_addr().unwrap())
    };
    let hang = Fb::start("127.0.0.2", |_| Resp::hang());
    for (uri, why) in [(dead, "refused"), (hang.base(), "timed out")] {
        let env = Env::new();
        env.config("ServiceTimeout: 1500, ServiceIdleTimeout: 300");
        env.services(std::slice::from_ref(&uri));
        let o = env.ext(&["cat", &label(b"x")]);
        assert_eq!(o.code, 5, "{}", o.stderr);
        let line = o
            .stderr
            .lines()
            .find(|l| l.starts_with(&format!("SERVICE {uri} ERROR ")))
            .unwrap_or_else(|| panic!("no ERROR line: {}", o.stderr));
        assert!(
            line.to_lowercase().contains(why),
            "message should say `{why}`: {line}"
        );
    }
}

/// ES-7: 4 is usage or configuration. An initialised index that has lost
/// its `files` table is a damaged store, where the blob may be indexed:
/// a lookup must fail loudly with 5, never 4 and never "absent".
/// Violator: reading the missing table as empty, or as a usage error.
#[test]
fn an_index_missing_its_table_is_a_store_error() {
    let env = setup(&[]);
    let b = blob(10, 2);
    env.index_file("f", &b);
    let c = rusqlite::Connection::open(env.store.join("index.db")).unwrap();
    c.execute_batch("DROP TABLE files").unwrap();
    drop(c);
    for cmd in ["resolve", "cat"] {
        let o = env.ext(&[cmd, &label(&b)]);
        assert_eq!(o.code, 5, "{cmd}: {}", o.stderr);
        assert!(
            o.stderr.contains("index"),
            "{cmd}: names the index: {}",
            o.stderr
        );
        assert!(o.stdout.is_empty());
    }
}
