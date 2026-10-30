//! The TLS path of the shipped binary (ES-17). The binary trusts the platform
//! store, and `SSL_CERT_FILE` is the one variable that may change it, so a
//! throwaway CA made at test time (rcgen) can be trusted by the real `ext`
//! with no test-only seam in the binary. Servers are rustls over loopback.
//!
//! Run: `cargo test --test svc_tls`.

mod svc;

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use svc::fb::{Fb, Resp};
use svc::*;

struct Ca {
    params: CertificateParams,
    key: KeyPair,
    pem: String,
}

fn ca(name: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    let pem = params.self_signed(&key).unwrap().pem();
    Ca { params, key, pem }
}

struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    key: PrivatePkcs8KeyDer<'static>,
}

/// A server certificate for `san` signed by `ca`; `expired` backdates it.
fn leaf(ca: &Ca, san: &str, expired: bool) -> Leaf {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.subject_alt_names = vec![SanType::IpAddress(san.parse().unwrap())];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    if expired {
        p.not_before = date_time_ymd(1990, 1, 1);
        p.not_after = date_time_ymd(1991, 1, 1);
    }
    let issuer = Issuer::from_params(&ca.params, &ca.key);
    let cert = p.signed_by(&key, &issuer).unwrap();
    Leaf { chain: vec![cert.der().clone()], key: PrivatePkcs8KeyDer::from(key.serialize_der()) }
}

struct TlsFb {
    addr: std::net::SocketAddr,
    served: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Drop for TlsFb {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = std::net::TcpStream::connect(self.addr);
    }
}

/// `blob = None` accepts TCP and then says nothing: a stalled handshake.
fn tls_fb(l: Leaf, blob: Option<Vec<u8>>) -> TlsFb {
    let listener = TcpListener::bind("127.0.0.2:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let cfg = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(l.chain, l.key.into())
            .unwrap(),
    );
    let (served2, stop2) = (served.clone(), stop.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            if stop2.load(Ordering::Relaxed) {
                return;
            }
            let Ok(tcp) = conn else { continue };
            let (cfg, blob, served, stop) = (cfg.clone(), blob.clone(), served2.clone(), stop2.clone());
            std::thread::spawn(move || {
                let Some(blob) = blob else {
                    while !stop.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    return;
                };
                let mut s = StreamOwned::new(ServerConnection::new(cfg).unwrap(), tcp);
                let mut head = vec![];
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if !matches!(s.read(&mut b), Ok(1)) {
                        return; // the client refused the handshake
                    }
                    head.push(b[0]);
                }
                served.fetch_add(1, Ordering::SeqCst);
                let _ = write!(s, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", blob.len());
                let _ = s.write_all(&blob);
                s.conn.send_close_notify();
                let _ = s.flush();
            });
        }
    });
    TlsFb { addr, served, stop }
}

fn env_for(fb: &TlsFb, extra: &str) -> Env {
    let env = Env::new();
    env.config_raw(&format!("{{ AllowLocal: true, {extra} }}"));
    env.services(&[format!("https://{}/", fb.addr)]);
    env
}

fn cat_with(env: &Env, b: &[u8], vars: &[(&str, &str)]) -> Out {
    env.ext_env(&["cat", &label(b)], vars, Duration::from_secs(20))
}

fn write_ca(env: &Env, name: &str, pem: &str) -> String {
    let p = env.base.join(name);
    fs::write(&p, pem).unwrap();
    p.to_str().unwrap().to_string()
}

/// ES-17. Certificate and hostname validation against the roots the platform
/// loader returns: a chain from the CA named by `SSL_CERT_FILE` with a matching
/// SAN is a Hit (the one positive https path); the same server presenting a
/// CA the file does not name, a certificate for another name, or an expired
/// one is Error. `SSLKEYLOGFILE` is ignored. Violators: certificate checking
/// off, hostname verification off (wrong SAN passes), expiry unchecked, roots
/// compiled in or SSL_CERT_FILE ignored (the positive case fails),
/// SSLKEYLOGFILE honoured.
#[test]
fn chain_name_and_expiry_are_validated_against_the_platform_roots() {
    let b = blob(500, 1);
    let good = ca("trusted");
    let other = ca("somebody else");

    let fb = tls_fb(leaf(&good, "127.0.0.2", false), Some(b.clone()));
    let env = env_for(&fb, "");
    let keylog = env.base.join("keylog");
    let trusted = write_ca(&env, "good.pem", &good.pem);
    let o = cat_with(&env, &b, &[("SSL_CERT_FILE", &trusted), ("SSLKEYLOGFILE", keylog.to_str().unwrap())]);
    assert_eq!((o.code, &o.stdout), (0, &b), "valid chain, matching SAN: {}", o.stderr);
    assert_eq!(fb.served.load(Ordering::SeqCst), 1);
    assert!(!keylog.exists(), "SSLKEYLOGFILE must be ignored");

    let untrusted = write_ca(&env, "other.pem", &other.pem);
    let o = cat_with(&env, &b, &[("SSL_CERT_FILE", &untrusted)]);
    assert_eq!(o.code, 5, "a chain from a CA the roots do not name: {}", o.stderr);
    assert!(o.stdout.is_empty());
    assert_eq!(fb.served.load(Ordering::SeqCst), 1, "no request was made over the refused session");

    for (what, l) in [
        ("wrong name", leaf(&good, "127.0.0.9", false)),
        ("expired", leaf(&good, "127.0.0.2", true)),
    ] {
        let fb = tls_fb(l, Some(b.clone()));
        let env = env_for(&fb, "");
        let trusted = write_ca(&env, "good.pem", &good.pem);
        let o = cat_with(&env, &b, &[("SSL_CERT_FILE", &trusted)]);
        assert_eq!(o.code, 5, "{what}: {}", o.stderr);
        assert!(o.stdout.is_empty(), "{what}");
        assert_eq!(fb.served.load(Ordering::SeqCst), 0, "{what}: no request over a session that failed validation");
    }
}

/// ES-17: when `SSL_CERT_FILE` names a file that is missing, not PEM, or holds
/// no certificate, the attempt is Error naming the path, and there is no
/// fallback to another root source. Violator: silently using other roots (the
/// path never appears in the message).
#[test]
fn a_bad_ssl_cert_file_is_an_error_naming_the_cause() {
    let b = blob(40, 2);
    let good = ca("trusted");
    let fb = tls_fb(leaf(&good, "127.0.0.2", false), Some(b.clone()));
    let env = env_for(&fb, "");
    let pem = write_ca(&env, "ok.pem", &good.pem);
    assert_eq!(cat_with(&env, &b, &[("SSL_CERT_FILE", &pem)]).code, 0, "control: the good file works");
    let garbled = env.base.join("garbled.pem");
    fs::write(&garbled, b"-----BEGIN CERTIFICATE-----\nnot base64 !!\n-----END CERTIFICATE-----\n").unwrap();
    let empty = env.base.join("empty.pem");
    fs::write(&empty, b"").unwrap();
    let missing = env.base.join("missing.pem");
    for p in [&garbled, &empty, &missing] {
        let o = cat_with(&env, &b, &[("SSL_CERT_FILE", p.to_str().unwrap())]);
        assert_eq!(o.code, 5, "{}: {}", p.display(), o.stderr);
        assert!(o.stderr.contains(p.to_str().unwrap()), "the cause names the path: {}", o.stderr);
        assert!(o.stdout.is_empty());
    }
}

/// ES-13 and ES-17: a server that accepts TCP and never speaks ends the
/// attempt at the timeout (the TLS phase counts against the total), with the
/// service named. Violator: no bound on the handshake.
#[test]
fn a_stalled_handshake_is_cut_off() {
    let good = ca("trusted");
    let fb = tls_fb(leaf(&good, "127.0.0.2", false), None);
    let env = env_for(&fb, "ServiceIdleTimeout: 300, ServiceTimeout: 1500");
    let trusted = write_ca(&env, "good.pem", &good.pem);
    let o = cat_with(&env, &blob(10, 1), &[("SSL_CERT_FILE", &trusted)]);
    assert_eq!(o.code, 5, "{}", o.stderr);
    assert!(o.elapsed >= Duration::from_millis(250) && o.elapsed < Duration::from_millis(2000 + 500), "{:?}", o.elapsed);
    assert!(o.stderr.contains(&format!("https://{}/", fb.addr)), "{}", o.stderr);
}

/// ES-17: proxy variables (any case) and resolver-altering variables are not
/// read. With every proxy variable pointing at a listener, the https fetch
/// still succeeds and the listener sees nothing; a plain-http service under
/// `AllowHTTP` is fetched directly too; `HOSTALIASES` mapping a bare name to
/// `localhost` changes nothing, so that name stays unresolvable. Violators:
/// proxy-from-environment, glibc's HOSTALIASES left in force.
#[test]
fn proxy_and_resolver_variables_are_ignored() {
    let b = blob(64, 3);
    let proxy = TcpListener::bind("127.0.0.2:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let url = format!("http://{}", proxy.local_addr().unwrap());
    let vars: Vec<(&str, &str)> = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"]
        .into_iter()
        .map(|k| (k, url.as_str()))
        .collect();
    let connections = || (0..50).filter(|_| proxy.accept().is_ok()).count();

    let good = ca("trusted");
    let fb = tls_fb(leaf(&good, "127.0.0.2", false), Some(b.clone()));
    let env = env_for(&fb, "");
    let trusted = write_ca(&env, "good.pem", &good.pem);
    let mut v = vars.clone();
    v.push(("SSL_CERT_FILE", &trusted));
    let o = cat_with(&env, &b, &v);
    assert_eq!((o.code, &o.stdout), (0, &b), "https fetch direct, not via a proxy: {}", o.stderr);

    let plain = Fb::blob("127.0.0.2", &b);
    let env = Env::new();
    env.config("");
    env.services(&[plain.base()]);
    let o = cat_with(&env, &b, &vars);
    assert_eq!((o.code, &o.stdout), (0, &b), "{}", o.stderr);
    assert_eq!(plain.requests().len(), 1, "the service itself saw the request");
    assert_eq!(connections(), 0, "the proxy listener was never contacted");

    let local = Fb::start("127.0.0.1", { let b = b.clone(); move |_| Resp::ok(&b) });
    let port = local.addr.port();
    let aliases = env.base.join("aliases");
    fs::write(&aliases, "alias-host localhost\n").unwrap();
    env.services(&[format!("http://alias-host:{port}/")]);
    let o = cat_with(&env, &b, &[("HOSTALIASES", aliases.to_str().unwrap())]);
    assert_eq!(o.code, 5, "an alias in HOSTALIASES must not make the name resolve: {}", o.stderr);
    assert!(local.requests().is_empty());
    env.services(&[format!("http://127.0.0.1:{port}/")]);
    assert_eq!(cat_with(&env, &b, &[]).code, 0, "control: that server is reachable by address");
}
