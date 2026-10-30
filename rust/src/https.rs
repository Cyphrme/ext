//! The `https` backend (ES-5, ES-9, ES-12 to ES-19, ES-23) on ureq 3,
//! synchronous, rustls, with a custom resolver and a constant allow-list.
//!
//! ureq is configured to do as little as possible on its own: no proxy, no
//! redirects (ext follows them itself, ES-14), no pooled connections (every
//! hop is resolved and judged afresh, ES-15), no status-as-error. The socket
//! is ext's own transport, so the idle and total limits of ES-13 bound every
//! read and write, the TLS handshake included, whatever ureq's own timers do.

use crate::cache::TmpFile;
use crate::digest::Alg;
use crate::lookup::{Backend, Fetched, Limits};
use crate::services::{self, Fetchable, Scheme, ServiceUri};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver as UreqResolver};
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, RustlsConnector, Transport,
};

/// ES-14: at most this many redirect hops.
const MAX_HOPS: usize = 5;

/// The resolver hook (S2): consulted once per hop, including for IP literals.
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// The platform resolver (getaddrinfo). An IP literal is parsed, not looked
/// up.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }
}

/// An allow-list of prefixes minus a deny-list (S3). Production passes
/// [`AddrTable::iana`].
#[derive(Clone, Debug)]
pub struct AddrTable {
    pub allow: Vec<(IpAddr, u8)>,
    pub deny: Vec<(IpAddr, u8)>,
}

fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> (IpAddr, u8) {
    (IpAddr::V4(Ipv4Addr::new(a, b, c, d)), len)
}

fn v6(segs: [u16; 8], len: u8) -> (IpAddr, u8) {
    let [a, b, c, d, e, f, g, h] = segs;
    (IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)), len)
}

impl AddrTable {
    /// The constant IANA special-purpose table of ES-15, from the IPv4 and
    /// IPv6 Special-Purpose Address Registries (RFC 6890 as updated). A
    /// block whose Globally Reachable value is False is denied whole, even
    /// where the registry marks a smaller block inside it True (192.0.0.9,
    /// 192.0.0.10, parts of 2001::/23): those are anycast and
    /// protocol-assignment addresses no blob service sits behind, and
    /// denying too much is the safe direction.
    pub fn iana() -> AddrTable {
        AddrTable {
            allow: vec![v4(0, 0, 0, 0, 0), v6([0x2000, 0, 0, 0, 0, 0, 0, 0], 3)],
            deny: vec![
                v4(0, 0, 0, 0, 8),                         // "this network"
                v4(10, 0, 0, 0, 8),                        // private use
                v4(100, 64, 0, 0, 10),                     // shared address space
                v4(127, 0, 0, 0, 8),                       // loopback
                v4(169, 254, 0, 0, 16),                    // link local
                v4(172, 16, 0, 0, 12),                     // private use
                v4(192, 0, 0, 0, 24),                      // IETF protocol assignments
                v4(192, 0, 2, 0, 24),                      // documentation (TEST-NET-1)
                v4(192, 88, 99, 0, 24),                    // deprecated 6to4 relay anycast
                v4(192, 168, 0, 0, 16),                    // private use
                v4(198, 18, 0, 0, 15),                     // benchmarking
                v4(198, 51, 100, 0, 24),                   // documentation (TEST-NET-2)
                v4(203, 0, 113, 0, 24),                    // documentation (TEST-NET-3)
                v4(224, 0, 0, 0, 4),                       // multicast (ES-15 names it)
                v4(240, 0, 0, 0, 4),                       // reserved, and limited broadcast
                v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),     // IETF protocol assignments
                v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32), // documentation
                v6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),     // documentation
            ],
        }
    }
}

fn contains(net: (IpAddr, u8), ip: IpAddr) -> bool {
    match (net.0, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let len = u32::from(net.1.min(32));
            let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let len = u32::from(net.1.min(128));
            let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

/// ES-15: judged after `IpAddr::to_canonical()`; 6to4 by its embedded IPv4;
/// Teredo denied; everything outside the table denied.
pub fn permitted(ip: IpAddr, table: &AddrTable) -> bool {
    let ip = match ip.to_canonical() {
        IpAddr::V6(a) => {
            let s = a.segments();
            if s[0] == 0x2002 {
                // 6to4 (2002::/16) reaches the IPv4 host it embeds.
                let [b0, b1] = s[1].to_be_bytes();
                let [b2, b3] = s[2].to_be_bytes();
                IpAddr::V4(Ipv4Addr::new(b0, b1, b2, b3))
            } else if s[0] == 0x2001 && s[1] == 0 {
                // Teredo (2001::/32) tunnels to a host nobody can judge.
                return false;
            } else {
                IpAddr::V6(a)
            }
        }
        v4 => v4,
    };
    table.allow.iter().any(|n| contains(*n, ip)) && !table.deny.iter().any(|n| contains(*n, ip))
}

/// ES-14: the scheme may change only between https and http, and only when
/// `allow_http`; the same scheme is always fine.
pub fn redirect_scheme_allowed(from: Scheme, to: Scheme, allow_http: bool) -> bool {
    from == to || allow_http
}

#[derive(Clone, Copy, Debug)]
pub struct HttpsConfig {
    pub allow_http: bool,
    pub allow_local: bool,
}

pub struct Client {
    cfg: HttpsConfig,
    resolver: Arc<dyn Resolver>,
    table: Arc<AddrTable>,
    /// Loaded once per process (ES-17); a failure is kept and becomes the
    /// `Error` of every attempt that needs TLS.
    roots: Result<Arc<Vec<Certificate<'static>>>, String>,
}

impl Client {
    /// Trust roots load once, before an attempt's ES-13 clock starts (ES-17);
    /// a load failure is an `Error` outcome of the attempt, not a failure here.
    pub fn new(cfg: HttpsConfig, resolver: Box<dyn Resolver>, table: AddrTable) -> Client {
        Client {
            cfg,
            resolver: Arc::from(resolver),
            table: Arc::new(table),
            roots: load_roots().map(Arc::new),
        }
    }

    pub fn backend(&self, uri: ServiceUri) -> HttpsBackend<'_> {
        HttpsBackend { client: self, uri }
    }

    /// One agent per attempt, so its transport and resolver carry that
    /// attempt's clock.
    fn agent(&self, budget: Budget) -> ureq::Agent {
        // With no usable roots an https hop is refused before ureq sees it;
        // an empty list keeps ureq off any default root source regardless.
        let roots = self.roots.clone().unwrap_or_default();
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .root_certs(RootCerts::Specific(roots))
            .build();
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .https_only(false)
            .proxy(None)
            .max_redirects(0)
            .save_redirect_history(false)
            .user_agent(format!("ext/{}", env!("CARGO_PKG_VERSION")))
            .accept("application/octet-stream")
            .accept_encoding("identity")
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .tls_config(tls)
            .build();
        let hook = Hook {
            inner: self.resolver.clone(),
            table: self.table.clone(),
            allow_local: self.cfg.allow_local,
            budget,
        };
        ureq::Agent::with_parts(
            config,
            Tcp { budget }.chain(RustlsConnector::default()),
            hook,
        )
    }
}

/// ES-17: the platform loader's roots, which `SSL_CERT_FILE` and
/// `SSL_CERT_DIR` alone may redirect, with no fallback.
fn load_roots() -> Result<Vec<Certificate<'static>>, String> {
    let named: Vec<String> = ["SSL_CERT_FILE", "SSL_CERT_DIR"]
        .into_iter()
        .filter_map(|k| std::env::var_os(k).map(|v| format!("{k}={}", v.to_string_lossy())))
        .collect();
    let source = if named.is_empty() {
        "the platform trust store".to_string()
    } else {
        named.join(" ")
    };
    let found = rustls_native_certs::load_native_certs();
    if !named.is_empty() && !found.errors.is_empty() {
        let why: Vec<String> = found.errors.iter().map(|e| e.to_string()).collect();
        return Err(format!(
            "cannot load trust roots from {source}: {}",
            why.join("; ")
        ));
    }
    let mut usable = rustls::RootCertStore::empty();
    let (added, _) = usable.add_parsable_certificates(found.certs.iter().cloned());
    if added == 0 {
        return Err(format!("no usable trust root in {source}"));
    }
    Ok(found
        .certs
        .iter()
        .map(|c| Certificate::from_der(c.as_ref()).to_owned())
        .collect())
}

pub struct HttpsBackend<'c> {
    client: &'c Client,
    uri: ServiceUri,
}

impl Backend for HttpsBackend<'_> {
    /// ES-23 names the algorithm in the URL, so every one is addressable.
    fn addresses(&self, _alg: Alg) -> bool {
        true
    }

    fn fetch(&self, d: &Fetchable, limits: &Limits, sink: TmpFile) -> Fetched {
        let mut sink = sink;
        match self.attempt(d, limits, &mut sink) {
            Ok(true) => Fetched::Hit(sink),
            Ok(false) => Fetched::Missing,
            Err(e) => Fetched::Error(e),
        }
    }
}

impl HttpsBackend<'_> {
    /// `Ok(true)`: a candidate is in `sink`. `Ok(false)`: Missing.
    fn attempt(&self, d: &Fetchable, limits: &Limits, sink: &mut TmpFile) -> Result<bool, String> {
        let cfg = self.client.cfg;
        if self.uri.scheme() == Scheme::Http && !cfg.allow_http {
            return Err("an http service needs AllowHTTP".into());
        }
        let budget = Budget {
            deadline: Instant::now() + limits.total,
            idle: limits.idle,
        };
        let agent = self.client.agent(budget);
        let mut url = self.uri.request_url(d);
        let mut scheme = self.uri.scheme();
        for hop in 0..=MAX_HOPS {
            if scheme == Scheme::Https {
                if let Err(e) = &self.client.roots {
                    return Err(e.clone());
                }
            }
            let resp = agent.get(&url).call().map_err(describe)?;
            let status = resp.status().as_u16();
            match status {
                200 => return read_body(resp, limits.max_size, sink).map(|()| true),
                403 | 404 | 410 => return Ok(false),
                301 | 302 | 303 | 307 | 308 => {
                    if hop == MAX_HOPS {
                        return Err(format!("more than {MAX_HOPS} redirects"));
                    }
                    let loc = resp
                        .headers()
                        .get("location")
                        .ok_or_else(|| format!("redirect {status} without a Location"))?;
                    let loc = std::str::from_utf8(loc.as_bytes())
                        .map_err(|_| "a Location that is not ASCII".to_string())?;
                    let (next_scheme, next) = resolve_reference(&url, loc)
                        .map_err(|e| format!("redirect to {loc}: {e}"))?;
                    if !redirect_scheme_allowed(scheme, next_scheme, cfg.allow_http)
                        || (next_scheme == Scheme::Http && !cfg.allow_http)
                    {
                        return Err(format!("redirect to {next} needs AllowHTTP"));
                    }
                    url = next;
                    scheme = next_scheme;
                }
                _ => return Err(format!("HTTP status {status}")),
            }
        }
        unreachable!("the last hop returns from inside the loop")
    }
}

fn describe(e: ureq::Error) -> String {
    match e {
        ureq::Error::Timeout(_) => {
            "timed out (ServiceIdleTimeout without progress, or ServiceTimeout in total)".into()
        }
        e => e.to_string(),
    }
}

/// ES-5, ES-9, ES-12: a 200's body into `sink`, never more than `max` bytes
/// written nor `max` + 1 read, whatever the headers claim.
fn read_body(
    resp: ureq::http::Response<ureq::Body>,
    max: u64,
    sink: &mut TmpFile,
) -> Result<(), String> {
    let headers = resp.headers();
    if let Some(ce) = headers.get("content-encoding") {
        let identity = ce
            .to_str()
            .is_ok_and(|v| v.trim().eq_ignore_ascii_case("identity"));
        if !identity {
            return Err("a Content-Encoding other than identity".into());
        }
    }
    // A claim may only make ext give up early (ES-9).
    if let Some(cl) = headers.get("content-length") {
        if let Some(n) = cl.to_str().ok().and_then(|v| v.trim().parse::<u64>().ok()) {
            if n > max {
                return Err(format!("Content-Length {n} is above ServiceMaxSize {max}"));
            }
        }
    }
    let mut body = resp.into_body().into_with_config().limit(u64::MAX).reader();
    let mut buf = vec![0u8; 64 << 10];
    let mut total: u64 = 0;
    loop {
        let room = max.saturating_add(1) - total;
        let want = usize::try_from(room).map_or(buf.len(), |r| r.min(buf.len()));
        let n = match body.read(&mut buf[..want]) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("reading the body: {e}")),
        };
        total += n as u64;
        if total > max {
            return Err(format!("the body is longer than ServiceMaxSize {max}"));
        }
        sink.file()
            .write_all(&buf[..n])
            .map_err(|e| format!("cannot write the candidate: {e}"))?;
    }
}

/// RFC 3986 section 5.2 reference resolution, then ES-14's grammar check of
/// the result. Returns the target's scheme and the URL.
fn resolve_reference(base: &str, r: &str) -> Result<(Scheme, String), String> {
    if r.contains('#') {
        return Err("a fragment is not allowed".into());
    }
    let has_scheme = r.split_once(':').is_some_and(|(s, _)| {
        s.starts_with(|c: char| c.is_ascii_alphabetic())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    });
    // The base was itself built from a valid line, so it splits.
    let b = services::split(base).map_err(|e| e.to_string())?;
    let base_scheme = match b.scheme {
        Scheme::Https => "https",
        Scheme::Http => "http",
    };
    let origin = format!("{base_scheme}://{}{}", b.host, b.port);
    let base_path = b.rest.split('?').next().unwrap_or("");
    let target = if has_scheme {
        r.to_string()
    } else if let Some(net) = r.strip_prefix("//") {
        format!("{base_scheme}://{net}")
    } else if r.starts_with('/') {
        format!("{origin}{r}")
    } else if r.is_empty() {
        base.to_string()
    } else if r.starts_with('?') {
        format!("{origin}{base_path}{r}")
    } else {
        let dir = base_path.rfind('/').map_or("/", |i| &base_path[..=i]);
        format!("{origin}{dir}{r}")
    };
    let t = services::split(&target).map_err(|e| e.to_string())?;
    let (path, query) = match t.rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (t.rest, None),
    };
    let path = remove_dot_segments(path);
    let rest = match query {
        Some(q) => format!("{path}?{q}"),
        None => path,
    };
    services::check_path(&rest, true, false).map_err(|e| e.to_string())?;
    let scheme_text = match t.scheme {
        Scheme::Https => "https",
        Scheme::Http => "http",
    };
    Ok((
        t.scheme,
        format!("{scheme_text}://{}{}{rest}", t.host, t.port),
    ))
}

/// RFC 3986 section 5.2.4.
fn remove_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut out: Vec<&str> = Vec::new();
    while !input.is_empty() {
        if let Some(r) = input.strip_prefix("../") {
            input = r;
        } else if let Some(r) = input.strip_prefix("./") {
            input = r;
        } else if input.starts_with("/./") {
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") || input == "/.." {
            input = if input == "/.." { "/" } else { &input[3..] };
            out.pop();
        } else if input == "." || input == ".." {
            input = "";
        } else {
            let start = usize::from(input.starts_with('/'));
            let end = input[start..].find('/').map_or(input.len(), |i| i + start);
            out.push(&input[..end]);
            input = &input[end..];
        }
    }
    out.concat()
}

/// The attempt's clock: each wait gets the idle limit or what is left of the
/// total, whichever is less (ES-13).
#[derive(Clone, Copy, Debug)]
struct Budget {
    deadline: Instant,
    idle: Duration,
}

impl Budget {
    fn left(&self) -> Option<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
    }

    fn next_wait(&self) -> Result<Duration, ureq::Error> {
        self.left()
            .map(|l| l.min(self.idle).max(Duration::from_millis(1)))
            .ok_or(ureq::Error::Timeout(ureq::Timeout::Global))
    }
}

/// ES-15: the hook is asked for every hop and every address it returns is
/// judged; ureq connects only to what passes.
struct Hook {
    inner: Arc<dyn Resolver>,
    table: Arc<AddrTable>,
    allow_local: bool,
    budget: Budget,
}

impl fmt::Debug for Hook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hook").finish_non_exhaustive()
    }
}

impl UreqResolver for Hook {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let host = uri
            .host()
            .ok_or_else(|| ureq::Error::BadUri("no host".into()))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        // getaddrinfo cannot be interrupted; a thread lets the total limit
        // apply to it anyway (ES-13's DNS backstop).
        let wait = self
            .budget
            .left()
            .ok_or(ureq::Error::Timeout(ureq::Timeout::Resolve))?;
        let (tx, rx) = mpsc::sync_channel(1);
        let (inner, h) = (self.inner.clone(), host.clone());
        std::thread::spawn(move || tx.send(inner.resolve(&h, port)).ok());
        let addrs = match rx.recv_timeout(wait) {
            Ok(r) => r.map_err(|e| {
                ureq::Error::Io(io::Error::new(e.kind(), format!("resolve {host}: {e}")))
            })?,
            Err(_) => return Err(ureq::Error::Timeout(ureq::Timeout::Resolve)),
        };
        let mut out = self.empty();
        for a in addrs
            .iter()
            .filter(|a| self.allow_local || permitted(a.ip(), &self.table))
            .take(16)
        {
            out.push(*a);
        }
        if out.is_empty() {
            let all: Vec<String> = addrs.iter().map(|a| a.ip().to_string()).collect();
            return Err(ureq::Error::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{host} has no global unicast address (AllowLocal is off): [{}]",
                    all.join(", ")
                ),
            )));
        }
        Ok(out)
    }
}

/// TCP under the attempt's clock.
#[derive(Debug)]
struct Tcp {
    budget: Budget,
}

impl Connector<()> for Tcp {
    type Out = Socket;

    fn connect(
        &self,
        details: &ConnectionDetails,
        _chained: Option<()>,
    ) -> Result<Option<Socket>, ureq::Error> {
        let mut last = None;
        for addr in &details.addrs {
            match TcpStream::connect_timeout(addr, self.budget.next_wait()?) {
                Ok(stream) => {
                    let config = details.config;
                    return Ok(Some(Socket {
                        stream,
                        buffers: LazyBuffers::new(
                            config.input_buffer_size(),
                            config.output_buffer_size(),
                        ),
                        budget: self.budget,
                    }));
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.map_or(ureq::Error::ConnectionFailed, |e| {
            if matches!(
                e.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) {
                ureq::Error::Timeout(ureq::Timeout::Connect)
            } else {
                ureq::Error::Io(e)
            }
        }))
    }
}

struct Socket {
    stream: TcpStream,
    buffers: LazyBuffers,
    budget: Budget,
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socket")
            .field("peer", &self.stream.peer_addr().ok())
            .finish()
    }
}

fn io_timeout(e: io::Error) -> ureq::Error {
    if matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        ureq::Error::Timeout(ureq::Timeout::Global)
    } else {
        ureq::Error::Io(e)
    }
}

impl Transport for Socket {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, _timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream
            .set_write_timeout(Some(self.budget.next_wait()?))?;
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output).map_err(io_timeout)
    }

    fn await_input(&mut self, _timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream
            .set_read_timeout(Some(self.budget.next_wait()?))?;
        let input = self.buffers.input_append_buf();
        let n = loop {
            match self.stream.read(input) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                r => break r.map_err(io_timeout)?,
            }
        };
        self.buffers.input_appended(n);
        Ok(n > 0)
    }

    /// Never reused: every hop connects afresh (ES-15).
    fn is_open(&mut self) -> bool {
        false
    }
}
